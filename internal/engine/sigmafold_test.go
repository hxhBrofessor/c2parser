package engine

import (
	"os"
	"strings"
	"testing"
	"time"

	"c2parser/internal/sigma"
)

// builtinRules loads the repo's built-in rules plus, if C2PARSER_SIGMA is
// set, a pinned SigmaHQ snapshot directory.
func builtinRules(t *testing.T) []*sigma.Rule {
	paths := []string{"../../rules/sigma"}
	if d := os.Getenv("C2PARSER_SIGMA"); d != "" {
		paths = append(paths, d)
	}
	rules, rep := sigma.Load(paths...)
	if len(rules) == 0 {
		t.Fatalf("no Sigma rules loaded: %+v", rep)
	}
	return rules
}

// v9 Phase 1.1: a Sigma hit on a host pair that already has a finding
// folds into it — no duplicate standalone "Sigma rule match" finding.
func TestSigmaFoldsIntoHostFinding(t *testing.T) {
	s := newSynth(t)
	ts := s.now
	c := s.tcp(ts, "10.9.3.32", 52100, "100.113.27.34", 80)
	havocUA := "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
	for i := 0; i < 20; i++ {
		ts = ts.Add(5 * time.Second)
		ts = c.Send(ts, true, httpReq("POST", "/", []string{"Host: 100.113.27.34", "User-Agent: " + havocUA, "Content-Type: */*"}, string(randB(64))), 1400)
		ts = c.Send(ts.Add(30*time.Millisecond), false, httpResp("HTTP/1.1 200 OK", []string{"Content-Type: application/octet-stream"}, ""), 1400)
	}
	c.Close(ts.Add(time.Second))
	for _, cfg := range []Config{{Sigma: builtinRules(t)}, {Sigma: builtinRules(t), TimingV2: true}} {
		res := s.analyze(cfg)
		for _, f := range res.Findings {
			if f.Category == CatSigma {
				t.Errorf("v2=%v: standalone Sigma finding duplicates the C2 finding: %s", cfg.TimingV2, f.Title)
			}
		}
		f := findBy(res, CatC2, "100.113.27.34")
		if f == nil {
			t.Fatalf("v2=%v: no C2 finding", cfg.TimingV2)
		}
		folded := false
		for _, sg := range f.Signals {
			folded = folded || strings.HasPrefix(sg.Name, "sigma:e1f2bf20")
		}
		if !folded {
			t.Errorf("v2=%v: Havoc Sigma rule not folded into the C2 finding: %+v", cfg.TimingV2, f.Signals)
		}
	}
}
