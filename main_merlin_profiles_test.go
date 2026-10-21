package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"c2parser/internal/engine"
	"c2parser/internal/report"
	"c2parser/internal/synth"
)

func TestMerlinCLIAndLibraryJSONEquivalent(t *testing.T) {
	const doc = `name: profile-parity-715
seed: 715
start: 2024-03-25T07:00:00Z
streams:
  - label: c2
    shape: neutral-http-test
    transport: http-keepalive
    server: 198.51.100.20
    topology: {clients: [10.5.0.20]}
    timing: {model: fixed, sleep: 1, jitter: 0, events: 2}
    content:
      method: POST
      uri: /?q=1
      headers:
        - 'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36'
        - 'Content-Type: application/octet-stream; charset=utf-8'
        - 'Authorization: Bearer eyJpayload'
      poll: {dist: fixed, min: 16}
      resp: {dist: fixed, min: 16}
`
	dir := t.TempDir()
	sc, err := synth.ParseScenario([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := synth.WriteFile(sc, dir)
	if err != nil {
		t.Fatal(err)
	}
	pcap := filepath.Join(dir, manifest.Path)
	res, err := engine.AnalyzeFile(pcap, engine.Config{})
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
	code := run([]string{"-no-banner", "-no-sigma", "-no-sigma-update", "-offline", "-json", "-min-score", "0", pcap})
	_ = w.Close()
	os.Stdout = oldStdout
	cli, readErr := io.ReadAll(r)
	_ = r.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if code != 0 {
		t.Fatalf("CLI exit=%d output=%s", code, cli)
	}
	if !bytes.Equal(cli, library.Bytes()) {
		t.Fatalf("CLI/library output differs\nCLI: %s\nLIB: %s", cli, library.Bytes())
	}
	if !strings.Contains(string(cli), "default_profile:merlin") {
		t.Fatalf("Merlin synthetic fixture did not trigger: %s", cli)
	}
	var rows []map[string]any
	if err := json.Unmarshal(cli, &rows); err != nil {
		t.Fatalf("invalid CLI JSON: %v", err)
	}
}
