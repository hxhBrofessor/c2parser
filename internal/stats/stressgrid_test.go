package stats

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
)

// Stress grid cells (v9 Phase 0.3). Each cell is a detection rate (beacons)
// or false-positive rate (nulls) over 300 seeded replicates. Baselines live
// in testdata/stress_baseline.json: "v1" (ScoreBeacon ≥ 0.55) and one entry
// per released v2 engine. TestStressGateVsBest fails when v2 drops below
// max(v1, last release) − 0.03 on a detection cell, unless the cell is
// listed with a reason in docs/stress-tradeoffs.md (mirrored in
// stressTradeoffs below).

type cell struct {
	name   string
	null   bool // FP cell (lower is better)
	g      gen
	art    artifact
	n      int
	fixed  bool // null cell with fixed (C2-like) sizes: worst case for the size look
	seed   uint64
	budget float64 // FP budget for null cells
}

func gridCells() []cell {
	var cs []cell
	for _, nm := range []string{"poisson", "gamma0.5", "gamma4", "browsing"} {
		for _, n := range []int{30, 200} {
			b := 0.01
			if n == 200 {
				b = 0.0034
			}
			cs = append(cs, cell{name: fmt.Sprintf("null/%s/n%d/random-size", nm, n), null: true, g: nullGen(nm), n: n, seed: 1, budget: b})
			cs = append(cs, cell{name: fmt.Sprintf("null/%s/n%d/fixed-size", nm, n), null: true, g: nullGen(nm), n: n, fixed: true, seed: 1, budget: 0.03})
		}
	}
	for _, pol := range []string{"shorten", "lengthen", "symmetric", "anchored"} {
		for _, j := range []float64{0, 0.3, 0.5, 0.7, 0.9} {
			for _, n := range []int{15, 30, 60, 200} {
				cs = append(cs, cell{name: fmt.Sprintf("beacon/%s/%02.0f/n%d/clean", pol, j*100, n), g: beaconGen(pol, 60, j), n: n, seed: 2})
			}
		}
	}
	for _, pol := range []string{"shorten", "lengthen", "symmetric"} {
		for _, j := range []float64{0.1, 0.3, 0.7} {
			for _, a := range artifacts {
				if a.name == "clean" {
					continue
				}
				cs = append(cs, cell{name: fmt.Sprintf("artifact/%s/%02.0f/n60/%s", pol, j*100, a.name), g: beaconGen(pol, 60, j), art: a.f, n: 60, seed: 3})
			}
		}
	}
	return cs
}

// measure returns (v1, v2) rates for a cell.
func (c cell) measure() (float64, float64) {
	v1, v2, _ := rate(c.g, c.art, c.n, 60, !c.null || c.fixed, c.seed)
	return v1, v2
}

type baselineFile map[string]map[string]float64 // engine → cell → rate

func loadBaseline(t *testing.T) baselineFile {
	b, err := os.ReadFile("testdata/stress_baseline.json")
	if err != nil {
		t.Fatalf("stress baseline: %v", err)
	}
	var bf baselineFile
	if err := json.Unmarshal(b, &bf); err != nil {
		t.Fatal(err)
	}
	return bf
}

// TestStressBaselineWrite records the current engine's grid under the name
// in C2PARSER_STRESS_WRITE (e.g. "v8b"), plus "v1". Run once per release.
func TestStressBaselineWrite(t *testing.T) {
	name := os.Getenv("C2PARSER_STRESS_WRITE")
	if name == "" {
		t.Skip("set C2PARSER_STRESS_WRITE=<release> to record a stress baseline")
	}
	bf := baselineFile{}
	if b, err := os.ReadFile("testdata/stress_baseline.json"); err == nil {
		_ = json.Unmarshal(b, &bf)
	}
	bf["v1"], bf[name] = map[string]float64{}, map[string]float64{}
	for _, c := range gridCells() {
		v1, v2 := c.measure()
		bf["v1"][c.name], bf[name][c.name] = v1, v2
	}
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	out, _ := json.MarshalIndent(bf, "", " ")
	if err := os.WriteFile("testdata/stress_baseline.json", out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func sortedKeys(m map[string]float64) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}
