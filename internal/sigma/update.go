package sigma

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Auto-update of the SigmaHQ rule corpus, in the spirit of
// `nuclei -update-templates`: a cheap "what is the latest commit?" check at
// most once per MaxAge, a download only when the commit changed, a local
// cache that keeps working offline, and a pinnable ref.
//
// Two transports, tried in order:
//  1. HTTPS: GitHub API for the commit SHA, codeload tarball for content.
//  2. git:   `git ls-remote` + sparse shallow clone (if git is installed).
//
// Only the rule folders c2parser can evaluate are extracted.

// RulePrefixes are the corpus folders relevant to packet-derived events.
var RulePrefixes = []string{
	"rules/network/", "rules/web/", "rules-emerging-threats/", "rules-threat-hunting/network/", "rules-threat-hunting/web/",
}

// UpdateOptions configures Update.
type UpdateOptions struct {
	CacheDir   string        // default: <user cache dir>/c2parser/sigma
	Repo       string        // default: SigmaHQ/sigma
	Ref        string        // branch, tag or SHA; default: HEAD (default branch)
	MaxAge     time.Duration // re-check interval; default 24h
	Force      bool          // check now regardless of MaxAge
	Offline    bool          // never touch the network
	Timeout    time.Duration // per network operation; default 60s
	APIBase    string        // default https://api.github.com (tests override)
	TarBase    string        // default https://codeload.github.com (tests override)
	GitURL     string        // default https://github.com/<Repo>.git
	DisableGit bool
	HTTPClient *http.Client
	Log        io.Writer
}

// UpdateState is persisted next to the cache.
type UpdateState struct {
	Repo      string    `json:"repo"`
	Ref       string    `json:"ref"`
	SHA       string    `json:"sha"`
	Dir       string    `json:"dir"`
	Files     int       `json:"files"`
	CheckedAt time.Time `json:"checked_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Transport string    `json:"transport"`
}

// UpdateResult tells the caller what happened.
type UpdateResult struct {
	State   UpdateState
	Checked bool   // a remote check happened this run
	Updated bool   // new content was downloaded
	Note    string // human-readable status
}

func (o *UpdateOptions) defaults() error {
	if o.CacheDir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			base = os.TempDir()
		}
		o.CacheDir = filepath.Join(base, "c2parser", "sigma")
	}
	if o.Repo == "" {
		o.Repo = "SigmaHQ/sigma"
	}
	if o.MaxAge == 0 {
		o.MaxAge = 24 * time.Hour
	}
	if o.Timeout == 0 {
		o.Timeout = 60 * time.Second
	}
	if o.APIBase == "" {
		o.APIBase = "https://api.github.com"
	}
	if o.TarBase == "" {
		o.TarBase = "https://codeload.github.com"
	}
	if o.GitURL == "" {
		o.GitURL = "https://github.com/" + o.Repo + ".git"
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: o.Timeout} // honours HTTPS_PROXY
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	if !regexp.MustCompile(`^[\w.-]+/[\w.-]+$`).MatchString(o.Repo) {
		return fmt.Errorf("bad repo %q", o.Repo)
	}
	if o.Ref != "" && !regexp.MustCompile(`^[\w./-]+$`).MatchString(o.Ref) {
		return fmt.Errorf("bad ref %q", o.Ref)
	}
	return os.MkdirAll(o.CacheDir, 0o755)
}

func (o *UpdateOptions) statePath() string { return filepath.Join(o.CacheDir, "state.json") }

func loadState(p string) (UpdateState, bool) {
	var s UpdateState
	b, err := os.ReadFile(p)
	if err != nil || json.Unmarshal(b, &s) != nil || s.Dir == "" {
		return s, false
	}
	if fi, err := os.Stat(s.Dir); err != nil || !fi.IsDir() {
		return s, false
	}
	return s, true
}

func saveState(p string, s UpdateState) error {
	b, _ := json.MarshalIndent(s, "", "  ")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Update makes sure a current copy of the rules is cached and returns its
// directory. Network failures fall back to the cache when one exists.
func Update(ctx context.Context, o UpdateOptions) (UpdateResult, error) {
	if err := o.defaults(); err != nil {
		return UpdateResult{}, err
	}
	st, have := loadState(o.statePath())
	if have && (st.Repo != o.Repo || o.Ref != "" && st.Ref != o.Ref) {
		have = false // cache is for a different repo/ref
	}
	res := UpdateResult{State: st}
	switch {
	case o.Offline && have:
		res.Note = fmt.Sprintf("offline: using cached rules %s (%s)", short(st.SHA), st.UpdatedAt.Format("2006-01-02"))
		return res, nil
	case o.Offline:
		return res, errors.New("offline and no cached Sigma rules (run once with network, or pass -sigma <dir>)")
	case have && !o.Force && time.Since(st.CheckedAt) < o.MaxAge:
		res.Note = fmt.Sprintf("rules %s checked %s ago (next check in %s)", short(st.SHA),
			time.Since(st.CheckedAt).Round(time.Minute), (o.MaxAge - time.Since(st.CheckedAt)).Round(time.Minute))
		return res, nil
	}

	ref := o.Ref
	if ref == "" {
		ref = "HEAD"
	}
	sha, transport, err := o.latestSHA(ctx, ref)
	if err != nil {
		if have {
			res.Note = fmt.Sprintf("update check failed (%v); using cached rules %s", err, short(st.SHA))
			return res, nil
		}
		return res, fmt.Errorf("sigma update: %w", err)
	}
	res.Checked = true
	if have && sha == st.SHA {
		st.CheckedAt = time.Now()
		_ = saveState(o.statePath(), st)
		res.State = st
		res.Note = fmt.Sprintf("rules up to date (%s)", short(sha))
		return res, nil
	}
	fmt.Fprintf(o.Log, "sigma: downloading %s@%s via %s…\n", o.Repo, short(sha), transport)
	dir, n, err := o.fetch(ctx, sha, transport)
	if err != nil {
		if have {
			res.Note = fmt.Sprintf("download failed (%v); using cached rules %s", err, short(st.SHA))
			return res, nil
		}
		return res, fmt.Errorf("sigma download: %w", err)
	}
	old := st.Dir
	st = UpdateState{Repo: o.Repo, Ref: o.Ref, SHA: sha, Dir: dir, Files: n, CheckedAt: time.Now(), UpdatedAt: time.Now(), Transport: transport}
	if err := saveState(o.statePath(), st); err != nil {
		return res, err
	}
	if old != "" && old != dir && strings.HasPrefix(old, o.CacheDir) {
		os.RemoveAll(old)
	}
	res.State, res.Updated = st, true
	res.Note = fmt.Sprintf("updated rules to %s (%d files)", short(sha), n)
	return res, nil
}

func short(s string) string {
	if len(s) > 10 {
		return s[:10]
	}
	return s
}

var shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

func (o *UpdateOptions) latestSHA(ctx context.Context, ref string) (string, string, error) {
	sha, herr := o.apiSHA(ctx, ref)
	if herr == nil {
		return sha, "https", nil
	}
	if o.DisableGit {
		return "", "", herr
	}
	sha, gerr := o.gitSHA(ctx, ref)
	if gerr == nil {
		return sha, "git", nil
	}
	return "", "", fmt.Errorf("https: %v; git: %v", herr, gerr)
}

func (o *UpdateOptions) apiSHA(ctx context.Context, ref string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/repos/%s/commits/%s", o.APIBase, o.Repo, ref), nil)
	req.Header.Set("Accept", "application/vnd.github.sha")
	req.Header.Set("User-Agent", "c2parser-sigma-updater")
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := o.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub API %s", resp.Status)
	}
	sha := strings.TrimSpace(string(b))
	if !shaRe.MatchString(sha) {
		return "", fmt.Errorf("unexpected API response %q", short(sha))
	}
	return sha, nil
}

func (o *UpdateOptions) gitSHA(ctx context.Context, ref string) (string, error) {
	if shaRe.MatchString(ref) {
		return ref, nil
	}
	if _, err := exec.LookPath("git"); err != nil {
		return "", errors.New("git not installed")
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "ls-remote", o.GitURL, ref).Output()
	if err != nil {
		return "", fmt.Errorf("git ls-remote: %v", err)
	}
	for _, l := range strings.Split(string(out), "\n") {
		if f := strings.Fields(l); len(f) == 2 && shaRe.MatchString(f[0]) {
			return f[0], nil
		}
	}
	return "", fmt.Errorf("ref %q not found", ref)
}

func (o *UpdateOptions) fetch(ctx context.Context, sha, transport string) (string, int, error) {
	tmp, err := os.MkdirTemp(o.CacheDir, "dl-")
	if err != nil {
		return "", 0, err
	}
	var n int
	if transport == "https" {
		n, err = o.fetchTarball(ctx, sha, tmp)
	} else {
		n, err = o.fetchGit(ctx, sha, tmp)
	}
	if err == nil && n == 0 {
		err = errors.New("archive contained no rule files")
	}
	if err != nil {
		os.RemoveAll(tmp)
		return "", 0, err
	}
	final := filepath.Join(o.CacheDir, "rules-"+sha)
	os.RemoveAll(final)
	if err := os.Rename(tmp, final); err != nil {
		os.RemoveAll(tmp)
		return "", 0, err
	}
	return final, n, nil
}

const maxArchive = 512 << 20

func wanted(rel string) bool {
	if ext := strings.ToLower(filepath.Ext(rel)); ext != ".yml" && ext != ".yaml" {
		return false
	}
	for _, p := range RulePrefixes {
		if strings.HasPrefix(rel, p) {
			return true
		}
	}
	return false
}

func (o *UpdateOptions) fetchTarball(ctx context.Context, sha, dst string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*o.Timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/%s/tar.gz/%s", o.TarBase, o.Repo, sha), nil)
	req.Header.Set("User-Agent", "c2parser-sigma-updater")
	resp, err := o.HTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("download %s", resp.Status)
	}
	gz, err := gzip.NewReader(io.LimitReader(resp.Body, maxArchive))
	if err != nil {
		return 0, err
	}
	tr := tar.NewReader(gz)
	n := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		// strip the "<repo>-<sha>/" top directory
		parts := strings.SplitN(h.Name, "/", 2)
		if len(parts) != 2 {
			continue
		}
		rel := filepath.ToSlash(filepath.Clean(parts[1]))
		if strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) || !wanted(rel) || h.Size > 1<<20 {
			continue // path traversal guard, size guard, irrelevant files
		}
		out := filepath.Join(dst, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return n, err
		}
		f, err := os.Create(out)
		if err != nil {
			return n, err
		}
		_, err = io.Copy(f, io.LimitReader(tr, 1<<20))
		f.Close()
		if err != nil {
			return n, err
		}
		n++
	}
}

func (o *UpdateOptions) fetchGit(ctx context.Context, sha, dst string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*o.Timeout)
	defer cancel()
	work := dst + "-git"
	defer os.RemoveAll(work)
	run := func(dir string, args ...string) error {
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		return 0, err
	}
	steps := [][]string{
		{"init", "-q"},
		{"remote", "add", "origin", o.GitURL},
		{"sparse-checkout", "set", "--no-cone"},
		{"fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", sha},
	}
	for _, p := range RulePrefixes {
		steps[2] = append(steps[2], "/"+p)
	}
	for _, s := range steps {
		if err := run(work, s...); err != nil {
			return 0, err
		}
	}
	if err := run(work, "checkout", "-q", "FETCH_HEAD"); err != nil {
		return 0, err
	}
	n := 0
	err := filepath.WalkDir(work, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() && d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(work, p)
		rel = filepath.ToSlash(rel)
		if !wanted(rel) {
			return nil
		}
		out := filepath.Join(dst, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		if err := os.Rename(p, out); err != nil {
			return err
		}
		n++
		return nil
	})
	return n, err
}
