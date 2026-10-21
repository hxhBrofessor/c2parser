package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"c2parser/internal/engine"
	"c2parser/internal/report"
	"c2parser/internal/synth"
)

func TestCobaltStrikeCLIAndLibraryJSONEquivalent(t *testing.T) {
	scenario := `name: http-profile-parity
seed: 73
start: 2024-03-25T07:00:00Z
streams:
  - label: c2
    shape: neutral-http-test
    transport: http-keepalive
    server: 198.51.100.73
    topology: {clients: [10.5.0.73]}
    timing: {model: fixed, sleep: 1, jitter: 0, events: 1}
    content:
      method: POST
      uri: /submit.php?id=73
      headers:
        - 'Content-Type: application/octet-stream'
      poll: {dist: fixed, min: 16}
      resp: {dist: fixed, min: 16}
`
	dir := t.TempDir()
	sc, err := synth.ParseScenario([]byte(scenario))
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
	var lib bytes.Buffer
	if err := report.JSON(&lib, []*engine.Result{res}, report.Options{MinScore: 0}); err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	code := run([]string{"-no-banner", "-no-sigma", "-no-sigma-update", "-offline", "-json", "-min-score", "0", pcap})
	_ = w.Close()
	os.Stdout = old
	cli, readErr := io.ReadAll(r)
	_ = r.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if code != 0 {
		t.Fatalf("CLI exit %d: %s", code, cli)
	}
	if !bytes.Equal(cli, lib.Bytes()) {
		t.Fatalf("CLI/library JSON differ\nCLI %s\nLIB %s", cli, lib.Bytes())
	}
	if !strings.Contains(string(cli), "default_profile:cobalt_strike") {
		t.Fatalf("Cobalt profile signal absent: %s", cli)
	}
}
