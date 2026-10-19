package sigma

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testRule = `title: Test DNS
id: 11111111-2222-3333-4444-555555555555
level: high
logsource:
    category: dns
detection:
    sel:
        query|endswith: '.evil.example'
    condition: sel
`

func tarball(t *testing.T, top string, files map[string]string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		tw.WriteHeader(&tar.Header{Name: top + "/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

type fakeGitHub struct {
	sha       atomic.Value
	apiHits   atomic.Int32
	tarHits   atomic.Int32
	down      atomic.Bool
	srv       *httptest.Server
	tarballFn func(sha string) []byte
}

func newFake(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{}
	f.sha.Store(strings.Repeat("a", 40))
	f.tarballFn = func(sha string) []byte {
		return tarball(t, "sigma-"+sha, map[string]string{
			"rules/network/dns/net_test.yml":           testRule,
			"rules/windows/process_creation/proc.yml":  "title: x", // filtered out (folder)
			"rules/network/README.md":                  "docs",     // filtered out (ext)
			"../../escape.yml":                         testRule,   // path traversal attempt
			"rules-emerging-threats/2026/x/net_et.yml": strings.Replace(testRule, "1111", "9999", 1),
		})
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.down.Load() {
			http.Error(w, "nope", 503)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/repos/SigmaHQ/sigma/commits/"):
			f.apiHits.Add(1)
			w.Write([]byte(f.sha.Load().(string)))
		case strings.HasPrefix(r.URL.Path, "/SigmaHQ/sigma/tar.gz/"):
			f.tarHits.Add(1)
			w.Write(f.tarballFn(strings.TrimPrefix(r.URL.Path, "/SigmaHQ/sigma/tar.gz/")))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) opts(dir string) UpdateOptions {
	return UpdateOptions{CacheDir: dir, APIBase: f.srv.URL, TarBase: f.srv.URL, DisableGit: true, Timeout: 5 * time.Second}
}

func TestUpdateLifecycle(t *testing.T) {
	f := newFake(t)
	dir := t.TempDir()
	ctx := context.Background()

	// 1. first run downloads and filters
	r, err := Update(ctx, f.opts(dir))
	if err != nil || !r.Updated || r.State.Files != 2 {
		t.Fatalf("first run: %+v %v", r, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "escape.yml")); err == nil {
		t.Fatal("path traversal wrote outside the cache")
	}
	rules, rep := Load(r.State.Dir)
	if len(rules) != 2 || rep.ByKind["dns"] != 2 {
		t.Fatalf("loaded %d rules %+v", len(rules), rep)
	}

	// 2. within MaxAge: no network at all
	r, err = Update(ctx, f.opts(dir))
	if err != nil || r.Checked || f.apiHits.Load() != 1 {
		t.Fatalf("cached run touched network: %+v api=%d", r, f.apiHits.Load())
	}

	// 3. forced check, same SHA: API hit, no download
	o := f.opts(dir)
	o.Force = true
	r, err = Update(ctx, o)
	if err != nil || !r.Checked || r.Updated || f.tarHits.Load() != 1 {
		t.Fatalf("same-sha forced: %+v tar=%d", r, f.tarHits.Load())
	}

	// 4. new upstream commit: download, old dir removed
	old := r.State.Dir
	f.sha.Store(strings.Repeat("b", 40))
	r, err = Update(ctx, o)
	if err != nil || !r.Updated || r.State.SHA != strings.Repeat("b", 40) {
		t.Fatalf("new sha: %+v %v", r, err)
	}
	if _, err := os.Stat(old); err == nil {
		t.Error("old rules dir not cleaned up")
	}

	// 5. GitHub down: fall back to cache, no error
	f.down.Store(true)
	r, err = Update(ctx, o)
	if err != nil || r.Updated || !strings.Contains(r.Note, "using cached") {
		t.Fatalf("fallback: %+v %v", r, err)
	}

	// 6. offline with cache works; offline without cache errors
	o.Offline = true
	if _, err := Update(ctx, o); err != nil {
		t.Fatal(err)
	}
	o.CacheDir = t.TempDir()
	if _, err := Update(ctx, o); err == nil {
		t.Fatal("offline with empty cache should error")
	}
}

func TestUpdateRejectsBadRef(t *testing.T) {
	o := UpdateOptions{CacheDir: t.TempDir(), Ref: "main; rm -rf /", DisableGit: true}
	if _, err := Update(context.Background(), o); err == nil {
		t.Fatal("bad ref accepted")
	}
}

// Live check through git (C2PARSER_LIVE_SIGMA=1). Exercises the fallback
// transport against the real repository.
func TestUpdateLiveGit(t *testing.T) {
	if os.Getenv("C2PARSER_LIVE_SIGMA") == "" {
		t.Skip("set C2PARSER_LIVE_SIGMA=1")
	}
	o := UpdateOptions{CacheDir: t.TempDir(), APIBase: "http://127.0.0.1:1", Timeout: 120 * time.Second, Log: os.Stderr}
	r, err := Update(context.Background(), o)
	if err != nil || r.State.Transport != "git" || r.State.Files < 100 {
		t.Fatalf("%+v %v", r, err)
	}
	rules, rep := Load(r.State.Dir)
	t.Logf("%s: %d files, %d loaded %v", r.Note, rep.Files, len(rules), rep.ByKind)
}
