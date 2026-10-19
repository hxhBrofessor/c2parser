package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	sy "c2parser/internal/synth"
)

// corpusScenarios loads corpus/scenarios/*.yaml.
func corpusScenarios(t *testing.T) []*sy.Scenario {
	t.Helper()
	files, _ := filepath.Glob("../../corpus/scenarios/*.yaml")
	if len(files) == 0 {
		t.Fatal("no corpus scenarios")
	}
	sort.Strings(files)
	var out []*sy.Scenario
	for _, f := range files {
		sc, err := sy.LoadScenario(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out = append(out, sc)
	}
	return out
}

// Candidate collection is opt-in and must preserve every existing primary
// result across the entire scenario corpus and both engine modes.
func TestCandidateModePreservesCorpusPrimaryOutputs(t *testing.T) {
	if testing.Short() {
		t.Skip("corpus candidate compatibility run")
	}
	scenarios := corpusScenarios(t)
	if len(scenarios) != 45 {
		t.Fatalf("corpus has %d scenarios; expected 45", len(scenarios))
	}
	for _, sc := range scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			var buf bytes.Buffer
			if _, err := sy.Generate(sc, &buf); err != nil {
				t.Fatal(err)
			}
			ext := ".pcap"
			if sc.Format == "pcapng" {
				ext = ".pcapng"
			}
			path := filepath.Join(t.TempDir(), sc.Name+ext)
			if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, cfg := range []Config{{}, {TimingV2: true}} {
				before, err := AnalyzeFile(path, cfg)
				if err != nil {
					t.Fatal(err)
				}
				after, _, err := AnalyzeFileWithCandidates(path, cfg)
				if err != nil {
					t.Fatal(err)
				}
				b1, err := json.Marshal(before)
				if err != nil {
					t.Fatal(err)
				}
				b2, err := json.Marshal(after)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(b1, b2) {
					t.Fatalf("candidate collection changed primary output (TimingV2=%v)", cfg.TimingV2)
				}
			}
		})
	}
}

// analyzeScenario generates sc and runs the engine on it.
func analyzeScenario(t *testing.T, sc *sy.Scenario, cfg Config) *Result {
	t.Helper()
	var buf bytes.Buffer
	if _, err := sy.Generate(sc, &buf); err != nil {
		t.Fatal(err)
	}
	ext := ".pcap"
	if sc.Format == "pcapng" {
		ext = ".pcapng"
	}
	p := filepath.Join(t.TempDir(), sc.Name+ext)
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := AnalyzeFile(p, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// v9 rev 2 Phase 1.4: the Phase 0.1 cap gates (and any other `expect`
// rows) expressed as corpus scenarios, under both engines. Scenarios with
// no expectations must still parse cleanly; their top findings are logged
// (docs/corpus.md records them).
func TestCorpusScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("corpus run")
	}
	for _, sc := range corpusScenarios(t) {
		t.Run(sc.Name, func(t *testing.T) {
			for _, cfg := range []Config{{}, {TimingV2: true}} {
				eng := map[bool]string{false: "v1", true: "v2"}[cfg.TimingV2]
				res := analyzeScenario(t, sc, cfg)
				var top []string
				for _, f := range res.Findings {
					if f.Score >= 0.2 && len(top) < 4 {
						top = append(top, fmt.Sprintf("%.2f %s", f.Score, f.Title))
					}
				}
				t.Logf("%s: %s", eng, strings.Join(top, " | "))
				for _, ex := range sc.Expect {
					if ex.Engine != eng {
						continue
					}
					f := corpusFinding(res, ex.Server, ex.Client, ex.Category)
					s := 0.0
					if f != nil {
						s = f.Score
					}
					if s < ex.Min || (ex.Max > 0 && s > ex.Max) {
						t.Errorf("%s %s client=%s: score %.2f outside [%.2f, %.2f] %s", eng, ex.Server, ex.Client, s, ex.Min, ex.Max, ex.Note)
					}
					if ex.Evidence != "" && (f == nil || !containsSub(append(append([]string{}, f.Evidence...), signalNames(f)...), ex.Evidence)) {
						t.Errorf("%s %s client=%s: %q not in evidence/signals of %v", eng, ex.Server, ex.Client, ex.Evidence, f)
					}
				}
			}
		})
	}
}

// corpusFinding is the highest-scoring finding of the expected category
// (default: C2 channel) naming server (and client, when given).
func corpusFinding(res *Result, server, client, category string) *Finding {
	want := map[string]string{"": CatC2, "recon": CatRecon, "lateral": CatLateral}[category]
	var best *Finding
	for i := range res.Findings {
		f := &res.Findings[i]
		if category != "any" && f.Category != want || !strings.Contains(f.Title, server) {
			continue
		}
		if client != "" && f.Client != client && !strings.Contains(f.Title, client) {
			continue
		}
		if best == nil || f.Score > best.Score {
			best = f
		}
	}
	return best
}

// v9 rev 2 Phase 0.1 gates over 30 seeds per scenario (the single-seed
// fixtures can pass by luck):
//   - v2: every single-host timing-only beacon ≥ 0.6, never above 0.84;
//   - v1: never capped to medium (the 0.39 cap is not applied to single
//     hosts) and the median ≥ 0.6. v1's raw score varies with the drawn
//     response sizes (0.51–0.64 on HTTPS with 200–599 B responses); that is
//     v1 scoring since v6, not the cap, and is recorded in
//     the v9 review rather than tuned here;
//   - fleet of 3: ≤ 0.39 for every seed, both engines.
func TestCapGateSeedSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("seed sweep")
	}
	const seeds = 30
	for _, sc := range corpusScenarios(t) {
		if !strings.HasPrefix(sc.Name, "gate-single-") && !strings.HasPrefix(sc.Name, "gate-tiny-") && !strings.HasPrefix(sc.Name, "gate-fleet3") {
			continue
		}
		ex := sc.Expect[0]
		fleet := strings.HasPrefix(sc.Name, "gate-fleet3")
		for _, cfg := range []Config{{}, {TimingV2: true}} {
			eng := map[bool]string{false: "v1", true: "v2"}[cfg.TimingV2]
			var xs []float64
			for seed := uint64(1); seed <= seeds; seed++ {
				sc.Seed = seed
				f := corpusFinding(analyzeScenario(t, sc, cfg), ex.Server, ex.Client, ex.Category)
				if f == nil {
					t.Errorf("%s %s seed %d: no finding", sc.Name, eng, seed)
					continue
				}
				xs = append(xs, f.Score)
				switch {
				case fleet && f.Score > TimingOnlyCap:
					t.Errorf("%s %s seed %d: fleet %.2f > %.2f", sc.Name, eng, seed, f.Score, TimingOnlyCap)
				case !fleet && f.Score > TimingOnlyMax:
					t.Errorf("%s %s seed %d: %.2f above critical cap", sc.Name, eng, seed, f.Score)
				case !fleet && cfg.TimingV2 && f.Score < 0.6:
					t.Errorf("%s v2 seed %d: %.2f < 0.6", sc.Name, seed, f.Score)
				case !fleet && f.Score <= TimingOnlyCap:
					t.Errorf("%s %s seed %d: single host capped to %.2f: %v", sc.Name, eng, seed, f.Score, f.Evidence)
				}
			}
			if len(xs) == seeds && !fleet {
				sort.Float64s(xs)
				t.Logf("%s %s: min %.2f median %.2f max %.2f", sc.Name, eng, xs[0], xs[seeds/2], xs[seeds-1])
				if xs[seeds/2] < 0.6 {
					t.Errorf("%s %s: median %.2f < 0.6", sc.Name, eng, xs[seeds/2])
				}
			}
		}
	}
}

// Mutation check for the fleet gate: with the fleet check disabled the
// 3-client corpus scenario is no longer capped (≥ 0.4), so the gate above
// is testing the fleet check and not something incidental.
func TestFleetGateMutation(t *testing.T) {
	sc, err := sy.LoadScenario("../../corpus/scenarios/gate-fleet3-https-60s.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func(v int) { fleetMinClients = v }(fleetMinClients)
	fleetMinClients = 1 << 30
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		f := corpusFinding(analyzeScenario(t, sc, cfg), "198.51.100.50", "10.50.0.11", "")
		if f == nil || f.Score < 0.4 {
			t.Errorf("v2=%v: fleet check disabled but the 3-client fixture still scores %v", cfg.TimingV2, scoreOf(f))
		}
	}
}

// D1 (v9b review): the engine-level trade-off rows in
// docs/stress-tradeoffs.md name real, swept scenarios.
func TestEngineTradeoffsDocumented(t *testing.T) {
	b, err := os.ReadFile("../../docs/stress-tradeoffs.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	_, sec, ok := strings.Cut(doc, "## Engine-level trade-offs")
	if !ok {
		t.Fatal("engine-level trade-off section missing")
	}
	names := map[string]bool{}
	for _, sc := range corpusScenarios(t) {
		names[sc.Name] = true
	}
	n := 0
	for _, line := range strings.Split(sec, "\n") {
		if !strings.HasPrefix(line, "| gate-") {
			continue
		}
		name := strings.TrimSpace(strings.Split(line, "|")[1])
		if !names[name] {
			t.Errorf("trade-off row %q names no corpus scenario", name)
		}
		if !strings.HasPrefix(name, "gate-single-") && !strings.HasPrefix(name, "gate-tiny-") {
			t.Errorf("trade-off row %q is not covered by TestCapGateSeedSweep", name)
		}
		n++
	}
	if n == 0 {
		t.Error("no engine-level trade-off rows")
	}
}

func containsSub(xs []string, sub string) bool {
	for _, x := range xs {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}

func signalNames(f *Finding) []string {
	var out []string
	for _, s := range f.Signals {
		out = append(out, s.Name)
	}
	return out
}

// scenarioScore runs a corpus scenario and returns the best C2 score for
// (server, client) under cfg.
func scenarioScore(t *testing.T, name, server, client string, cfg Config) float64 {
	t.Helper()
	sc, err := sy.LoadScenario("../../corpus/scenarios/" + name + ".yaml")
	if err != nil {
		t.Fatal(err)
	}
	if f := corpusFinding(analyzeScenario(t, sc, cfg), server, client, ""); f != nil {
		return f.Score
	}
	return 0
}

// Mutation checks for the v9c D2/D3 rules: each gate scenario flips when
// its rule is removed, so the gates test the rules and nothing incidental.
func TestV9cRuleMutations(t *testing.T) {
	type mut struct {
		name           string
		apply, restore func()
		scenario       string
		server, client string
		wantMin        float64 // mutated score must be ≥ wantMin …
		wantMax        float64 // … or ≤ wantMax (0 = unused)
	}
	save := func() (int, float64, int, bool, bool) {
		return fleetMinClients, fleetFrac, pollerMinTargets, gapShapes, wgPortAware
	}
	fm, ff, pm, gs, wg := save()
	restore := func() { fleetMinClients, fleetFrac, pollerMinTargets, gapShapes, wgPortAware = fm, ff, pm, gs, wg }
	muts := []mut{
		{"poller rule removed", func() { pollerMinTargets = 1 << 30 }, restore, "gate-poller-scrape", "10.70.0.21", "", 0.4, 0},
		{"gap shapes removed (MDM)", func() { gapShapes = false }, restore, "gate-scheduler-mdm", "198.51.100.85", "", 0.4, 0},
		{"gap shapes removed (updater)", func() { gapShapes = false }, restore, "gate-scheduler-browser-updater", "198.51.100.86", "", 0.4, 0},
		{"WireGuard port test removed", func() { wgPortAware = false }, restore, "gate-wireguard-dns-port", "198.51.100.80", "", 0, 0.39},
		{"absolute fleet threshold of 2 (v9b)", func() { fleetMinClients, fleetFrac = 2, 0 }, restore, "gate-fleet20", "198.51.100.91", "10.60.0.1", 0, 0.39},
	}
	for _, m := range muts {
		for _, cfg := range []Config{{}, {TimingV2: true}} {
			m.apply()
			s := scenarioScore(t, m.scenario, m.server, m.client, cfg)
			m.restore()
			if (m.wantMax == 0 && s < m.wantMin) || (m.wantMax > 0 && s > m.wantMax) {
				t.Errorf("%s v2=%v: %s still scores %.2f — the gate does not test the rule", m.name, cfg.TimingV2, m.scenario, s)
			}
		}
	}
}

// v9c 2.1: a beacon over 3 redirector IPs behind one SNI gives one v2
// finding keyed by (client, name), at the true period, scoring at least the
// best per-IP finding v9b produced; no per-IP findings remain. v1 has no K1
// series and is unchanged.
func TestK1RollupRedirectors(t *testing.T) {
	for _, mode := range []string{"round-robin", "random"} {
		name := "shape-https-redirectors-" + mode + "-3"
		sc, err := sy.LoadScenario("../../corpus/scenarios/" + name + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		cfg := Config{TimingV2: true}
		k1Rollup = false
		old := analyzeScenario(t, sc, cfg)
		k1Rollup = true
		best := 0.0
		for _, f := range old.Findings {
			if f.Category == CatC2 && strings.Contains(f.Title, "203.0.113.2") {
				best = math.Max(best, f.Score)
			}
		}
		res := analyzeScenario(t, sc, cfg)
		var roll []Finding
		for _, f := range res.Findings {
			if f.Category != CatC2 {
				continue
			}
			if strings.Contains(f.Title, "static-"+mode+".example") {
				roll = append(roll, f)
			} else if strings.Contains(f.Title, "203.0.113.2") {
				t.Errorf("%s: per-IP finding left: %s", mode, f.Title)
			}
		}
		if len(roll) != 1 {
			t.Fatalf("%s: %d roll-up findings, want 1", mode, len(roll))
		}
		if roll[0].Score < best {
			t.Errorf("%s: roll-up %.2f < best per-IP %.2f", mode, roll[0].Score, best)
		}
		k1 := seriesBy(res, "rollup", "K1|10.5.0.37|static-"+mode+".example")
		if k1 == nil || k1.Timing == nil || math.Abs(k1.Timing.PeriodSec-57) > 6 {
			t.Errorf("%s: K1 series period %+v, want ≈ 57 s (60 s × (1 − 0.05))", mode, k1)
		}
		t.Logf("%s: roll-up %.2f (best per-IP %.2f), K1 period %.1fs", mode, roll[0].Score, best, k1.Timing.PeriodSec)
		if v1 := analyzeScenario(t, sc, Config{}); len(v1.Findings) > 0 && strings.Contains(v1.Findings[0].Title, "K1") {
			t.Errorf("v1 changed: %s", v1.Findings[0].Title)
		}
	}
}

// v9c 2.2: a WebSocket upgraded with "Accept-Type: Push" is push_or_saas:
// its timing series is refused with that reason; poll mode is unchanged.
func TestWebSocketPushRefused(t *testing.T) {
	for name, wantRefused := range map[string]bool{"shape-websocket-push": true, "shape-websocket-poll": false} {
		sc, err := sy.LoadScenario("../../corpus/scenarios/" + name + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		res := analyzeScenario(t, sc, Config{TimingV2: true})
		var ws *TimingSeries
		for i := range res.Timing {
			if res.Timing[i].Site == "websocket" {
				ws = &res.Timing[i]
			}
		}
		if ws == nil {
			t.Fatalf("%s: no websocket timing series", name)
		}
		if got := ws.Refused == "event_model:"+ModelPush; got != wantRefused {
			t.Errorf("%s: refused=%q, want push refusal %v", name, ws.Refused, wantRefused)
		}
	}
	if !wsPushHeader("push") || !wsPushHeader("json, Push") || wsPushHeader("pushy") || wsPushHeader("") {
		t.Error("wsPushHeader parsing")
	}
}

// v9c 3.3: releasing parser state of closed connections and sweeping their
// lookup entries changes nothing a user sees: every corpus scenario gives
// identical findings (title, score, evidence, signals) and summaries with
// compaction on and off.
func TestCompactionNoop(t *testing.T) {
	if testing.Short() {
		t.Skip("corpus run")
	}
	render := func(r *Result) string {
		var b strings.Builder
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "%s|%.4f|%s|%v|", f.Title, f.Score, strings.Join(f.Evidence, ";"), signalNames(&f))
		}
		fmt.Fprintf(&b, "%d http %d dns %d talkers %+v", len(r.HTTP), len(r.DNS), len(r.TopTalkers), r.Counters)
		return b.String()
	}
	defer func() { compactClosed = true }()
	for _, sc := range corpusScenarios(t) {
		for _, cfg := range []Config{{}, {TimingV2: true}} {
			compactClosed = false
			a := render(analyzeScenario(t, sc, cfg))
			compactClosed = true
			b := render(analyzeScenario(t, sc, cfg))
			if a != b {
				t.Errorf("%s v2=%v: compaction changed the output\n off: %.400s\n on:  %.400s", sc.Name, cfg.TimingV2, a, b)
			}
		}
	}
}
