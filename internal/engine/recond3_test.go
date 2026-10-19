package engine

import (
	"testing"

	sy "c2parser/internal/synth"
)

// reconStream is an attack-shaped LDAP stream from client to a DC.
func reconStream(client, dc string) sy.Stream {
	return sy.Stream{Label: "c2", Shape: "recon=ldap", Transport: "ldap", Server: dc,
		Topology: sy.Topology{Clients: []string{client}},
		Timing:   sy.Timing{Model: "poisson", Sleep: 300, Events: 2},
		Content:  sy.Content{Preset: "recon"}}
}

// v10a.1 D3 (a): a fleet- or scheduler-capped series never takes recon.
// The join is decided on the capped score, so the fleet member keeps its
// 0.39 cap and the recon stands alone, capped at medium.
func TestReconNotJoinedToCappedSeries(t *testing.T) {
	sc, err := sy.LoadScenario("../../corpus/scenarios/gate-fleet3-https-60s.yaml")
	if err != nil {
		t.Fatal(err)
	}
	sc.Streams = append(sc.Streams, reconStream("10.50.0.11", "10.50.0.200"))
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		res := analyzeScenario(t, sc, cfg)
		for _, f := range res.Findings {
			if f.Category == CatC2 && f.Client == "10.50.0.11" {
				if hasSignal(&f, "recon_from_c2_host") || f.Score > TimingOnlyCap {
					t.Errorf("v2=%v: capped fleet member took recon: %.2f %+v", cfg.TimingV2, f.Score, f.Signals)
				}
			}
		}
		r := reconFindings(res)
		if len(r) != 1 || !hasSignal(r[0], "ldap_uac_delegation") || r[0].Client != "10.50.0.11" || r[0].Score > reconMax {
			t.Errorf("v2=%v: want one standalone recon finding ≤ %.2f, got %+v", cfg.TimingV2, reconMax, r)
		}
	}
}

// v10a.1 D3 (b): recon on top of timing-only evidence never reaches
// critical. Mutation: without the cap the same finding is critical.
// (Also: TestReconCappedJoinMutation below for (a).)
func TestReconNeverMakesTimingOnlyCritical(t *testing.T) {
	sc := &sy.Scenario{Name: "d3-strong-beacon", Seed: 77, Streams: []sy.Stream{
		{Label: "c2", Shape: "hosts=1", Transport: "https-keepalive", Server: "198.51.100.150", Name: "steady.example",
			Topology: sy.Topology{Clients: []string{"10.87.0.5"}},
			Timing:   sy.Timing{Model: "shortening", Sleep: 30, Jitter: 0.02, Events: 1000},
			Content:  sy.Content{Poll: sy.Size{Min: 120}, Resp: sy.Size{Min: 200}}},
		reconStream("10.87.0.5", "10.87.0.10"),
	}}
	run := func(cfg Config) *Finding {
		return corpusFinding(analyzeScenario(t, sc, cfg), "198.51.100.150", "10.87.0.5", "")
	}
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		f := run(cfg)
		if f == nil || !hasSignal(f, "recon_from_c2_host") {
			t.Fatalf("v2=%v: no recon on the beacon: %+v", cfg.TimingV2, f)
		}
		if f.Score > TimingOnlyMax || f.Severity == "critical" {
			t.Errorf("v2=%v: timing + recon reached %.2f (%s)", cfg.TimingV2, f.Score, f.Severity)
		}
	}
	reconCapTiming = false
	defer func() { reconCapTiming = true }()
	if f := run(Config{}); f == nil || f.Score <= TimingOnlyMax {
		t.Errorf("mutation: without the cap the fixture stays ≤ %.2f (%+v) — it can't see the rule", TimingOnlyMax, f)
	}
}

// Mutation for (a): with the join reading the raw pre-cap score, the fleet
// member takes recon and escapes its 0.39 cap (the defect found while
// writing these tests).
func TestReconCappedJoinMutation(t *testing.T) {
	reconJoinCapAware = false
	defer func() { reconJoinCapAware = true }()
	sc, _ := sy.LoadScenario("../../corpus/scenarios/gate-fleet3-https-60s.yaml")
	sc.Streams = append(sc.Streams, reconStream("10.50.0.11", "10.50.0.200"))
	for _, f := range analyzeScenario(t, sc, Config{}).Findings {
		if f.Category == CatC2 && f.Client == "10.50.0.11" && f.Score <= TimingOnlyCap {
			t.Errorf("mutation: fleet member still capped (%.2f) — the test can't see the rule", f.Score)
		}
	}
}
