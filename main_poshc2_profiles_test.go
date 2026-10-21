package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"c2parser/internal/engine"
	"c2parser/internal/report"
	"c2parser/internal/synth"
)

func TestPoshC2CLIAndLibraryJSONEquivalent(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "posh-parity.pcap")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	builder, err := synth.NewPcap(f)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2024, 3, 25, 7, 0, 0, 0, time.UTC)
	conn := builder.TCP(start, "10.5.0.20", 51000, "198.51.100.20", 80)
	conn.Send(start.Add(3*time.Millisecond), true, synth.HTTPReq("GET", "/en-us/index.html", []string{"Host: fixture", "User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36", "Cookie: SessionID=fixture; SESSIONID=1552332971750"}, ""), 1400)
	conn.Send(start.Add(5*time.Millisecond), false, synth.HTTPResp("HTTP/1.1 404 Not Found", []string{"Server: Apache "}, "IIS ASP.NET 2.0.43451 Server"), 1400)
	conn.Close(start.Add(10 * time.Millisecond))
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	pcap := file
	res, err := engine.AnalyzeFile(pcap, engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var library bytes.Buffer
	if err := report.JSON(&library, []*engine.Result{res}, report.Options{MinScore: 0}); err != nil {
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
		t.Fatalf("CLI exit=%d output=%s", code, cli)
	}
	if !bytes.Equal(cli, library.Bytes()) {
		t.Fatalf("CLI/library JSON differs\\nCLI:%s\\nLIB:%s", cli, library.Bytes())
	}
	if !strings.Contains(string(cli), "default_profile:poshc2") || !strings.Contains(string(cli), "default_profile:covenant") {
		t.Fatalf("synthetic PoshC2 case did not trigger: %s", cli)
	}
	var rows []map[string]any
	if err := json.Unmarshal(cli, &rows); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}
