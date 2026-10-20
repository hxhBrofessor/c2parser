package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"c2parser/internal/engine"
	"c2parser/internal/report"
	"c2parser/internal/sigma"
	"c2parser/internal/synth"
)

// v9c 3.1: -j N gives byte-identical JSON to -j 1, in argument order.
func TestParallelIdentical(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for _, name := range []string{"shape-artifacts-http", "gate-fleet20", "shape-dns-txt-base32", "shape-smb-pipe-framed", "benign-models", "shape-https-proxy-connect"} {
		sc, err := synth.LoadScenario(filepath.Join("corpus/scenarios", name+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		me, err := synth.WriteFile(sc, dir)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, filepath.Join(dir, me.Path))
	}
	paths = append(paths, filepath.Join(dir, "missing.pcap")) // errors stay in place too
	render := func(jobs int, cfg engine.Config) string {
		var res []*engine.Result
		var b bytes.Buffer
		for _, r := range analyzeAll(paths, cfg, jobs) {
			if r.err != nil {
				b.WriteString("error:" + r.err.Error() + "\n")
				continue
			}
			res = append(res, r.res)
		}
		if err := report.JSON(&b, res, report.Options{MinScore: 0}); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	rules, _ := sigma.Load("rules/sigma")
	if len(rules) == 0 {
		t.Fatal("no built-in Sigma rules")
	}
	for _, cfg := range []engine.Config{{}, {TimingV2: true}, {Sigma: rules}, {TimingV2: true, Sigma: rules}} {
		one := render(1, cfg)
		for _, j := range []int{2, 4, 16} {
			if got := render(j, cfg); got != one {
				t.Errorf("v2=%v -j %d output differs from -j 1", cfg.TimingV2, j)
			}
		}
	}
}

func TestCovenantCLIAndLibraryJSONEquivalent(t *testing.T) {
	scenario := `name: profile-parity
seed: 91
start: 2024-03-25T07:00:00Z
streams:
  - label: c2
    shape: neutral-http-test
    transport: http-keepalive
    server: 198.51.100.10
    topology: {clients: [10.5.0.10]}
    timing: {model: fixed, sleep: 1, jitter: 0, events: 2}
    content:
      method: GET
      uri: /en-us/index.html
      headers:
        - 'User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36'
        - 'Cookie: SESSIONID=1552332971750'
      poll: {dist: fixed, min: 16}
      resp: {dist: fixed, min: 16}
`
	dir := t.TempDir()
	runCase := func(name, doc string, wantCovenant bool) {
		t.Helper()
		sc, err := synth.ParseScenario([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		caseDir := filepath.Join(dir, name)
		if err := os.Mkdir(caseDir, 0o700); err != nil {
			t.Fatal(err)
		}
		me, err := synth.WriteFile(sc, caseDir)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(caseDir, me.Path)
		res, err := engine.AnalyzeFile(path, engine.Config{})
		if err != nil {
			t.Fatal(err)
		}
		var library bytes.Buffer
		if err := report.JSON(&library, []*engine.Result{res}, report.Options{MinScore: 0}); err != nil {
			t.Fatal(err)
		}
		oldStdout := os.Stdout
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stdout = w
		code := run([]string{"-no-banner", "-no-sigma", "-no-sigma-update", "-offline", "-json", "-min-score", "0", path})
		_ = w.Close()
		os.Stdout = oldStdout
		cli, readErr := io.ReadAll(r)
		_ = r.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if code != 0 {
			t.Fatalf("%s CLI exit=%d output=%s", name, code, cli)
		}
		if !bytes.Equal(cli, library.Bytes()) {
			t.Fatalf("%s CLI/library JSON differ\nCLI: %s\nLIB: %s", name, cli, library.Bytes())
		}
		matched := bytes.Contains(cli, []byte("default_profile:covenant"))
		if matched != wantCovenant {
			t.Fatalf("%s Covenant match=%v, want %v: %s", name, matched, wantCovenant, cli)
		}
	}
	t.Run("positive", func(t *testing.T) { runCase("positive", scenario, true) })
	negative := strings.ReplaceAll(scenario, "profile-parity", "profile-parity-negative")
	negative = strings.ReplaceAll(negative, "/en-us/index.html", "/not-profile.html")
	negative = strings.ReplaceAll(negative, "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36", "Mozilla/5.0")
	negative = strings.ReplaceAll(negative, "SESSIONID=1552332971750", "sessionid=1552332971750")
	t.Run("negative", func(t *testing.T) { runCase("negative", negative, false) })
}

func TestCandidateDestinationRejectsProtectedAliases(t *testing.T) {
	dir := t.TempDir()
	sc, err := synth.LoadScenario(filepath.Join("corpus/scenarios", "shape-carrier-base32.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := synth.WriteFile(sc, dir)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, manifest.Path)
	before, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	aliases := map[string]string{"same-path": input}
	aliases["hard-link"] = filepath.Join(dir, "hardlink.json")
	if err := os.Link(input, aliases["hard-link"]); err != nil {
		t.Fatal(err)
	}
	aliases["symlink"] = filepath.Join(dir, "symlink.json")
	if err := os.Symlink(input, aliases["symlink"]); err != nil {
		t.Fatal(err)
	}
	for name, destination := range aliases {
		t.Run(name, func(t *testing.T) {
			code := run([]string{"-no-banner", "-no-sigma", "-offline", "-json", "-candidate-json", destination, input})
			if code != 64 {
				t.Fatalf("alias run exit=%d, want 64", code)
			}
			got, err := os.ReadFile(input)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, before) {
				t.Fatalf("protected input changed for %s alias", name)
			}
		})
	}

	if runtime.GOOS != "windows" {
		for _, special := range []string{"/dev/null", "/dev/stdout", "/dev/stderr"} {
			t.Run("special-"+filepath.Base(special), func(t *testing.T) {
				if _, err := os.Lstat(special); err != nil {
					t.Skipf("special path unavailable: %v", err)
				}
				protected, err := candidateProtectedFiles([]string{input}, os.Stdout, os.Stderr)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := openCandidateDestination(special, protected); err == nil {
					t.Fatalf("accepted unsafe special destination %q", special)
				}
			})
		}
	}
}

func TestCandidateSidecarAtomicFailurePreservesExistingFile(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "candidate.json")
	old := []byte("{\"previous\":\"complete\"}\n")
	if err := os.WriteFile(destination, old, 0o600); err != nil {
		t.Fatal(err)
	}
	writeFailure := errors.New("injected partial write failure")
	err := publishCandidateSidecar(destination, nil, func(w io.Writer) error {
		if _, err := io.WriteString(w, "[partial"); err != nil {
			return err
		}
		return writeFailure
	}, nil)
	if !errors.Is(err, writeFailure) {
		t.Fatalf("publish error=%v, want injected error", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, old) {
		t.Fatalf("failed publication changed previous sidecar: %q", got)
	}
	left, err := filepath.Glob(filepath.Join(dir, ".c2parser-candidates-*.tmp"))
	if err != nil || len(left) != 0 {
		t.Fatalf("temporary files remain after failed write: %v err=%v", left, err)
	}
	if err := writeCandidateSidecar(destination, nil, nil); err != nil {
		t.Fatalf("successful atomic replacement failed: %v", err)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("sidecar permissions=%#o, want 0600", info.Mode().Perm())
	}
	var reports []engine.DecodeCandidateReport
	if err := json.Unmarshal(mustReadFile(t, destination), &reports); err != nil {
		t.Fatalf("published sidecar is invalid JSON: %v", err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCandidateSidecarAnchoredPublicationSurvivesDestinationSwap(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "protected.pcap")
	inputBytes := []byte("disposable input capture")
	if err := os.WriteFile(input, inputBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	protectedInfo, err := os.Stat(input)
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(dir, "sidecar.json")
	err = publishCandidateSidecar(destination, []os.FileInfo{protectedInfo}, func(w io.Writer) error {
		_, err := io.WriteString(w, "{\"complete\":true}\n")
		return err
	}, func(root *os.Root, name string) error {
		// Simulate a hard-link swap after the final identity check. Rename
		// replaces the link itself and never truncates its protected inode.
		return os.Link(filepath.Join(root.Name(), "protected.pcap"), filepath.Join(root.Name(), name))
	})
	if err != nil {
		t.Fatal(err)
	}
	gotInput, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(gotInput, inputBytes) {
		t.Fatalf("raced protected input changed: %q err=%v", gotInput, err)
	}
	gotSidecar, err := os.ReadFile(destination)
	if err != nil || string(gotSidecar) != "{\"complete\":true}\n" {
		t.Fatalf("atomic sidecar content=%q err=%v", gotSidecar, err)
	}
}

func TestCandidateDestinationRejectsRelativeAliasAndAllowsNewRegularFile(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "capture.pcap")
	if err := os.WriteFile(input, []byte("capture"), 0o600); err != nil {
		t.Fatal(err)
	}
	protected, err := candidateProtectedFiles([]string{input})
	if err != nil {
		t.Fatal(err)
	}
	dest, err := openCandidateDestination(filepath.Join(dir, "new.json"), protected)
	if err != nil {
		t.Fatalf("safe new destination rejected: %v", err)
	}
	dest.close()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	if _, err := openCandidateDestination("./capture.pcap", protected); err == nil {
		t.Fatal("relative input alias accepted")
	}
	if _, err := openCandidateDestination(filepath.Join(dir, "missing", "sidecar.json"), protected); err == nil {
		t.Fatal("destination under a missing directory accepted")
	}
	if _, err := openCandidateDestination(dir, protected); err == nil {
		t.Fatal("directory destination accepted as a regular sidecar file")
	}
}

func TestCandidateDestinationProtectsFilesInsideInputDirectories(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	if err := os.Mkdir(rules, 0o700); err != nil {
		t.Fatal(err)
	}
	rule := filepath.Join(rules, "rule.yml")
	if err := os.WriteFile(rule, []byte("title: protected\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "candidate.json")
	if err := os.Link(rule, alias); err != nil {
		t.Fatal(err)
	}
	protected, err := candidateProtectedFiles([]string{rules})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openCandidateDestination(alias, protected); err == nil {
		t.Fatal("hard-link alias to nested protected input file accepted")
	}
}

func TestCandidateDestinationRejectsPrimaryOutputAlias(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, "primary.json")
	if err := os.WriteFile(primary, []byte("primary-output"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(primary, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = file
	t.Cleanup(func() {
		os.Stdout = oldStdout
		_ = file.Close()
	})
	protected, err := candidateProtectedFiles(nil, os.Stdout)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openCandidateDestination(primary, protected); err == nil {
		t.Fatal("candidate destination aliases primary stdout file")
	}
}

func TestCandidateAnalysisFailurePreservesExistingSidecar(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "broken.pcap")
	if err := os.WriteFile(input, []byte("not a packet capture"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(dir, "candidate.json")
	previous := []byte("[{\"previous\":\"complete\"}]\n")
	if err := os.WriteFile(destination, previous, 0o600); err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = null
	code := run([]string{"-no-banner", "-no-sigma", "-offline", "-json", "-candidate-json", destination, input})
	os.Stdout = oldStdout
	_ = null.Close()
	if code != 1 {
		t.Fatalf("analysis failure exit=%d, want 1", code)
	}
	got, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(got, previous) {
		t.Fatalf("failed analysis changed previous sidecar: %q err=%v", got, err)
	}
}

func TestCandidateJSONIsSeparateFromCLIPrimaryOutput(t *testing.T) {
	dir := t.TempDir()
	sc, err := synth.LoadScenario(filepath.Join("corpus/scenarios", "shape-carrier-base32.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := synth.WriteFile(sc, dir)
	if err != nil {
		t.Fatal(err)
	}
	pcap := filepath.Join(dir, manifest.Path)
	candidatePath := filepath.Join(dir, "candidates.json")
	runCapture := func(args ...string) (int, []byte) {
		t.Helper()
		old := os.Stdout
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stdout = w
		code := run(args)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		os.Stdout = old
		out, err := io.ReadAll(r)
		_ = r.Close()
		if err != nil {
			t.Fatal(err)
		}
		return code, out
	}
	baseArgs := []string{"-no-banner", "-no-sigma", "-offline", "-json", pcap}
	baseCode, baseOut := runCapture(baseArgs...)
	candidateArgs := append([]string{"-candidate-json", candidatePath}, baseArgs...)
	candidateCode, candidateOut := runCapture(candidateArgs...)
	if baseCode != 0 || candidateCode != 0 {
		t.Fatalf("CLI exit codes baseline=%d candidate=%d", baseCode, candidateCode)
	}
	if !bytes.Equal(baseOut, candidateOut) {
		t.Fatalf("candidate mode changed stdout primary JSON\nbaseline: %s\ncandidate: %s", baseOut, candidateOut)
	}
	encoded, err := os.ReadFile(candidatePath)
	if err != nil {
		t.Fatal(err)
	}
	var reports []engine.DecodeCandidateReport
	if err := json.Unmarshal(encoded, &reports); err != nil {
		t.Fatalf("candidate sidecar is not its separate schema: %v", err)
	}
	if len(reports) != 1 || len(reports[0].Candidates) == 0 {
		t.Fatalf("candidate sidecar missing report/candidates: reports=%d", len(reports))
	}
	textPath := filepath.Join(dir, "text-candidates.json")
	textBaseArgs := []string{"-no-banner", "-no-sigma", "-offline", pcap}
	textBaseCode, textBaseOut := runCapture(textBaseArgs...)
	textCandidateArgs := append([]string{"-candidate-json", textPath}, textBaseArgs...)
	textCandidateCode, textCandidateOut := runCapture(textCandidateArgs...)
	if textBaseCode != 0 || textCandidateCode != 0 || !bytes.Equal(textBaseOut, textCandidateOut) {
		t.Fatalf("candidate mode changed human-readable output: codes=%d/%d", textBaseCode, textCandidateCode)
	}
}
