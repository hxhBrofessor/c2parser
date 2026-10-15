package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression tests against the lab captures. Point C2PARSER_TESTDATA at the
// directory holding them; tests skip if a file is missing.
//
//	C2PARSER_TESTDATA=~/captures go test ./...
func capture(t *testing.T, contains string) string {
	dir := os.Getenv("C2PARSER_TESTDATA")
	if dir == "" {
		t.Skip("C2PARSER_TESTDATA not set")
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "*.pcap*"))
	for _, m := range matches {
		base := filepath.Base(m)
		if strings.Contains(base, contains) && !(contains == "http_c2_enum" && strings.Contains(base, "part2")) {
			return m
		}
	}
	t.Skipf("no capture matching %q in %s", contains, dir)
	return ""
}

// engines runs a capture test under both timing engines (v8a review #2:
// the Q5 default-flip gate needs every capture green under v1 and v2).
var engines = []struct {
	name string
	cfg  Config
}{{"v1", Config{}}, {"v2", Config{TimingV2: true}}}

// eachEngine runs a capture test under v1 and v2, each with and without
// Sigma (built-in rules + the C2PARSER_SIGMA snapshot if set) — v9 Phase
// 1.1: the CLI loads Sigma by default, so the FP budget must hold with it.
func eachEngine(t *testing.T, f func(t *testing.T, cfg Config)) {
	for _, e := range engines {
		t.Run(e.name, func(t *testing.T) { f(t, e.cfg) })
		cfg := e.cfg
		t.Run(e.name+"+sigma", func(t *testing.T) {
			cfg.Sigma = builtinRules(t)
			f(t, cfg)
		})
	}
}

func analyzeCapture(t *testing.T, contains string, cfg Config) *Result {
	res, err := AnalyzeFile(capture(t, contains), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func hasSignal(f *Finding, name string) bool {
	for _, s := range f.Signals {
		if s.Name == name && s.Score > 0 {
			return true
		}
	}
	return false
}

// noOtherFindings fails if anything not in `allowed` categories/titles
// scores ≥ 0.4 (medium) — our false-positive budget on lab traffic.
func noOtherFindings(t *testing.T, res *Result, allowed ...*Finding) {
	t.Helper()
outer:
	for _, f := range res.Findings {
		if f.Score < 0.4 {
			continue
		}
		for _, a := range allowed {
			if a != nil && a.Title == f.Title {
				continue outer
			}
		}
		t.Errorf("unexpected %s finding %.2f: %s %+v", f.Severity, f.Score, f.Title, f.Signals)
	}
}

func TestCaptureHTTPC2Enum(t *testing.T) {
	eachEngine(t, func(t *testing.T, cfg Config) {
		res := analyzeCapture(t, "http_c2_enum", cfg)
		if res.Counters.HTTPMessages != 1060 {
			t.Errorf("HTTP messages %d, want 1060 (tshark ground truth)", res.Counters.HTTPMessages)
		}
		c2 := findBy(res, CatC2, "100.113.27.34")
		if c2 == nil || c2.Score < 0.85 || !hasSignal(c2, "sig:havoc-demon-header") || !hasTimingSignal(c2) {
			t.Fatalf("Havoc HTTP C2 not detected: %+v", c2)
		}
		ex := findBy(res, CatExfil, "100.113.27.34")
		if ex == nil || ex.Score < 0.85 || !hasSignal(ex, "fixed_size_chunks") {
			t.Fatalf("8 MB exfil not detected: %+v", ex)
		}
		noOtherFindings(t, res, c2, ex)
	})
}

func TestCaptureHTTPC2EnumPart2(t *testing.T) {
	eachEngine(t, func(t *testing.T, cfg Config) {
		res := analyzeCapture(t, "part2", cfg)
		c2 := findBy(res, CatC2, "100.113.27.34")
		if c2 == nil || c2.Score < 0.85 {
			t.Fatalf("Havoc HTTP C2 not detected: %+v", c2)
		}
		up := findBy(res, CatExfil, "100.84.177.10")
		if up == nil || up.Score < 0.4 || !hasSignal(up, "http_file_upload") {
			t.Fatalf("updog upload of beacon4a.txt not detected: %+v", up)
		}
		noOtherFindings(t, res, c2, up)
	})
}

func TestCaptureSMB2Data(t *testing.T) {
	eachEngine(t, func(t *testing.T, cfg Config) {
		res := analyzeCapture(t, "smb2-data", cfg)
		p := findBy(res, CatPipe, "gainz")
		if p == nil || p.Score < 0.85 || !hasSignal(p, "c2_framing_in_pipe") {
			t.Fatalf("gainz pivot pipe not detected: %+v", p)
		}
		noOtherFindings(t, res, p)
	})
}

func TestCaptureSMB2Workstation(t *testing.T) {
	eachEngine(t, func(t *testing.T, cfg Config) {
		res := analyzeCapture(t, "smb2-wks", cfg)
		c2 := findBy(res, CatC2, "100.113.27.34")
		if c2 == nil || c2.Score < 0.85 {
			t.Fatalf("HTTP C2 not detected: %+v", c2)
		}
		var allowed = []*Finding{c2}
		pivots := 0
		for i := range res.Findings {
			f := &res.Findings[i]
			if f.Category == CatPipe && strings.Contains(f.Title, "gainz") {
				allowed = append(allowed, f)
				if hasSignal(f, "pivot_from_c2_host") && f.Score >= 0.85 {
					pivots++
				}
			}
		}
		if pivots == 0 {
			t.Fatal("pipe not correlated with the HTTP C2 host")
		}
		noOtherFindings(t, res, allowed...)
	})
}
