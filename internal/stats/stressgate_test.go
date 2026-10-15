package stats

import (
	"os"
	"regexp"
	"testing"
)

// lastRelease is the previous released v2 engine in testdata/stress_baseline.json.
const lastRelease = "v9.0"

// stressTradeoffs are cells allowed below max(v1, last release) − 0.03,
// with the reason letter used in docs/stress-tradeoffs.md.
var stressTradeoffs = map[string]string{
	"beacon/shorten/70/n15/clean":       "A",
	"beacon/symmetric/50/n15/clean":     "A",
	"beacon/symmetric/70/n15/clean":     "A",
	"beacon/symmetric/70/n30/clean":     "A",
	"beacon/symmetric/70/n60/clean":     "A",
	"beacon/anchored/50/n15/clean":      "A",
	"beacon/anchored/70/n15/clean":      "A",
	"beacon/anchored/90/n15/clean":      "A",
	"beacon/anchored/90/n30/clean":      "A",
	"beacon/anchored/90/n60/clean":      "A",
	"artifact/shorten/70/n60/miss20%":   "B",
	"artifact/shorten/70/n60/stall5%":   "C",
	"artifact/symmetric/70/n60/miss20%": "B",
	"artifact/symmetric/70/n60/stall5%": "C",
	"artifact/symmetric/70/n60/quant1s": "C",
}

// TestStressGateVsBest is the v9 stress gate (Phase 0.3): every detection
// cell ≥ max(v1, last release) − 0.03 unless it is a documented trade-off;
// every null cell within its FP budget. Cells where v2 < v1 − 0.1 are
// printed as a warning table either way.
func TestStressGateVsBest(t *testing.T) {
	bf := loadBaseline(t)
	last, ok := bf[lastRelease]
	if !ok {
		t.Fatalf("baseline has no %q entry", lastRelease)
	}
	var warn []string
	for _, c := range gridCells() {
		_, v2 := c.measure()
		if c.null {
			if v2 > c.budget {
				t.Errorf("FP %s: %.3f > budget %.3f", c.name, v2, c.budget)
			}
			continue
		}
		v1 := bf["v1"][c.name]
		best := max(v1, last[c.name])
		if v2 < v1-0.1 {
			warn = append(warn, c.name)
			t.Logf("WARN v2 < v1 − 0.1: %-40s v1 %.2f  %s %.2f  v2 %.2f", c.name, v1, lastRelease, last[c.name], v2)
		}
		if v2 < best-0.03 {
			if _, ok := stressTradeoffs[c.name]; !ok {
				t.Errorf("%s: v2 %.2f < max(v1 %.2f, %s %.2f) − 0.03 and not a documented trade-off", c.name, v2, v1, lastRelease, last[c.name])
			}
		} else if _, ok := stressTradeoffs[c.name]; ok {
			t.Logf("trade-off %s now meets max(v1, %s) — remove it from the list", c.name, lastRelease)
		}
	}
	t.Logf("%d cells with v2 < v1 − 0.1", len(warn))
}

// The trade-off list in code and docs/stress-tradeoffs.md must agree.
func TestStressTradeoffsDocumented(t *testing.T) {
	b, err := os.ReadFile("../../docs/stress-tradeoffs.md")
	if err != nil {
		t.Fatal(err)
	}
	inDoc := map[string]bool{}
	for _, m := range regexp.MustCompile("(?m)^\\| `([^`]+)`").FindAllStringSubmatch(string(b), -1) {
		inDoc[m[1]] = true
	}
	for k := range stressTradeoffs {
		if !inDoc[k] {
			t.Errorf("trade-off %s missing from docs/stress-tradeoffs.md", k)
		}
	}
	for k := range inDoc {
		if _, ok := stressTradeoffs[k]; !ok {
			t.Errorf("docs/stress-tradeoffs.md lists %s, the gate doesn't", k)
		}
	}
}
