package engine

import (
	"strings"
	"testing"

	"c2parser/internal/stats"
	sy "c2parser/internal/synth"
)

// v11a remediation F01: the timing-only, timing+URI-shape and
// timing+recon caps compose. Built on the independent reviewer's capture
// (seed 77, 1000-event 30 s keep-alive HTTP series, optional same-client
// AD recon via reconStream).

func capScenario(path string, recon, payload bool) *sy.Scenario {
	c := sy.Content{Method: "GET", URI: path, Encoding: "text", Resp: sy.Size{Min: 200},
		Headers: []string{"User-Agent: app/1.0", "Accept: */*"}}
	if payload {
		// Independent payload evidence that preserves the URI: every
		// response is a fresh random base64 body (encoded_payload_in_resp).
		// The poll stays empty, so each GET is exactly `path` and the URI
		// shapes (word-dot-ext, fixed-uri in v2) still fire on the same
		// capture. (Before the F01 recovery-audit correction the payload
		// rode in fresh ?d= query values, which made every URI distinct and
		// removed the URI-shape evidence the row claimed to test.)
		c.Encoding, c.Resp = "base64", sy.Size{Dist: "uniform", Min: 180, Max: 240}
	}
	sc := &sy.Scenario{Name: "cap-compose", Seed: 77, Streams: []sy.Stream{{Label: "c2", Shape: "hosts=1", Transport: "http-keepalive",
		Server: "198.51.100.150", Name: "steady.example", Topology: sy.Topology{Clients: []string{"10.87.0.5"}},
		Timing: sy.Timing{Model: "shortening", Sleep: 30, Jitter: .02, Events: 1000}, Content: c}}}
	if recon {
		sc.Streams = append(sc.Streams, reconStream("10.87.0.5", "10.87.0.10"))
	}
	return sc
}

type capRow struct {
	name          string
	path          string
	recon, payld  bool
	maxScore      float64 // 0 = must exceed TimingOnlyMax (independent payload lifts)
	guard         string  // expected cap evidence substring ("" = none required)
	needSignalsV2 []string
}

var capRows = []capRow{
	{"timing only", "/api/status", false, false, TimingOnlyMax, "", nil},
	{"timing + fixed URI (v2)", "/api/status", false, false, TimingOnlyMax, "", []string{"uri_shape:fixed-uri"}},
	{"timing + word.ext", "/updates.rss", false, false, TimingOnlyMax, "", []string{"uri_shape:word-dot-ext"}},
	{"timing + recon", "/api/status", true, false, TimingOnlyMax,
		"timing and AD recon are the only evidence: capped below critical", []string{"recon_from_c2_host"}},
	{"timing + recon + word.ext (+ fixed URI in v2)", "/updates.rss", true, false, TimingOnlyMax,
		"timing, AD recon and URI shape are the only evidence: capped below critical", []string{"recon_from_c2_host", "uri_shape:word-dot-ext"}},
	{"timing + recon + word.ext + payload", "/updates.rss", true, true, 0, "",
		[]string{"recon_from_c2_host", "uri_shape:word-dot-ext", "uri_shape:fixed-uri", "encoded_payload_in_resp"}},
}

// payloadRow is the composed capture plus independent payload evidence.
var payloadRow = capRows[5]

func runCapRow(t *testing.T, r capRow, cfg Config) *Finding {
	t.Helper()
	f := corpusFinding(analyzeScenario(t, capScenario(r.path, r.recon, r.payld), cfg), "198.51.100.150", "10.87.0.5", "")
	if f == nil {
		t.Fatalf("%s: no finding", r.name)
	}
	return f
}

func TestCapComposition(t *testing.T) {
	for _, r := range capRows {
		for _, cfg := range []Config{{}, {TimingV2: true}} {
			f := runCapRow(t, r, cfg)
			t.Logf("%-48s v2=%-5v %.2f %-8s %v | %s", r.name, cfg.TimingV2, f.Score, f.Severity, signalNames(f), capEvidence(f))
			if r.maxScore > 0 && f.Score > r.maxScore {
				t.Errorf("%s v2=%v: %.2f > %.2f", r.name, cfg.TimingV2, f.Score, r.maxScore)
			}
			if r.maxScore == 0 && f.Score <= TimingOnlyMax {
				t.Errorf("%s v2=%v: independent payload evidence must lift above %.2f, got %.2f", r.name, cfg.TimingV2, TimingOnlyMax, f.Score)
			}
			if r.guard != "" && !containsSub(f.Evidence, r.guard) {
				t.Errorf("%s v2=%v: guard %q not applied: %v", r.name, cfg.TimingV2, r.guard, f.Evidence)
			}
			for _, s := range r.needSignalsV2 {
				if (cfg.TimingV2 || s != "uri_shape:fixed-uri") && !hasSignal(f, s) {
					t.Errorf("%s v2=%v: fixture lacks %s: %v", r.name, cfg.TimingV2, s, signalNames(f))
				}
			}
		}
	}
}

func capEvidence(f *Finding) string {
	for _, e := range f.Evidence {
		if strings.Contains(e, "capped") {
			return e
		}
	}
	return "(no cap)"
}

// Each guard is load-bearing: removing it lifts the composed row above
// the cap; the benign fleet gates stay ≤ TimingOnlyCap with both on.
func TestCapCompositionMutations(t *testing.T) {
	composed := capRows[4]
	for _, m := range []struct {
		name  string
		apply func()
	}{
		{"recon guard off", func() { reconCapTiming = false }},
		{"URI-shape guard off", func() { uriShapeCapTiming = false }},
	} {
		for _, cfg := range []Config{{}, {TimingV2: true}} {
			m.apply()
			f := runCapRow(t, composed, cfg)
			reconCapTiming, uriShapeCapTiming = true, true
			if f.Score <= TimingOnlyMax {
				t.Errorf("%s v2=%v: still %.2f — the matrix does not test this guard", m.name, cfg.TimingV2, f.Score)
			}
		}
	}
	for _, g := range []struct{ scenario, server, client string }{
		{"gate-fleet3-http-fixed-uri", "198.51.100.111", "10.50.1.11"},
		{"gate-fleet3-http-word-dot-ext", "198.51.100.112", "10.50.2.11"},
		{"gate-poller-scrape", "10.70.0.21", ""},
		{"gate-scheduler-jamf", "", ""},
	} {
		for _, cfg := range []Config{{}, {TimingV2: true}} {
			if g.server == "" {
				sc, _ := sy.LoadScenario("../../corpus/scenarios/" + g.scenario + ".yaml")
				for _, f := range analyzeScenario(t, sc, cfg).Findings {
					if f.Category == CatC2 && f.Score > TimingOnlyCap {
						t.Errorf("%s v2=%v: %s %.2f", g.scenario, cfg.TimingV2, f.Title, f.Score)
					}
				}
				continue
			}
			if s := scenarioScore(t, g.scenario, g.server, g.client, cfg); s > TimingOnlyCap {
				t.Errorf("%s v2=%v: %.2f > %.2f", g.scenario, cfg.TimingV2, s, TimingOnlyCap)
			}
		}
	}
}

// The predicate itself, on the reviewer's minimal signal set.
func TestTimingPlusReconComposesURIShape(t *testing.T) {
	s := []stats.Signal{{Name: "beacon_timing", Weight: .8, Score: 1}, {Name: "recon_from_c2_host", Weight: .5, Score: 1},
		{Name: "uri_shape:word-dot-ext", Weight: .3, Score: 1}}
	if !timingPlusRecon(s) {
		t.Error("timing+recon+URI shape not recognised as timing+recon")
	}
	uriShapeCapTiming = false
	defer func() { uriShapeCapTiming = true }()
	if timingPlusRecon(s) {
		t.Error("with the URI-shape guard off the URI shape must count as evidence")
	}
	uriShapeCapTiming = true
	if timingPlusRecon(append(s, stats.Signal{Name: "encoded_payload_in_query", Weight: .55, Score: 1})) {
		t.Error("independent payload evidence must not be capped")
	}
}

// F01 recovery-audit correction: the payload row is the composed
// timing + recon + URI-shape capture *plus* independent payload evidence,
// on the same capture and the same URI. Asserts, in both engines:
//   - the constellation: timing, recon_from_c2_host, uri_shape:word-dot-ext
//     (and uri_shape:fixed-uri in v2) and encoded_payload_in_resp, all
//     contributing ≥ negligible;
//   - the cap invariants: without the payload signal the very same signal
//     set is timing + recon (+ URI shape) and takes the ≤ TimingOnlyMax
//     cap; with it, no cap applies and no cap evidence is written;
//   - the legitimate lift: the finding exceeds both TimingOnlyMax and the
//     same capture without payload (the capped composed row), by the
//     payload contribution alone.
func TestCapCompositionPayloadLift(t *testing.T) {
	composed := capRows[4]
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		f := runCapRow(t, payloadRow, cfg)
		base := runCapRow(t, composed, cfg)
		t.Logf("v2=%-5v payload %.2f %s %v | without payload %.2f %s | %s",
			cfg.TimingV2, f.Score, f.Severity, signalNames(f), base.Score, base.Severity, capEvidence(f))

		want := []string{"recon_from_c2_host", "uri_shape:word-dot-ext", "encoded_payload_in_resp"}
		if cfg.TimingV2 {
			want = append(want, "uri_shape:fixed-uri")
		}
		timed := false
		for _, s := range f.Signals {
			timed = timed || stats.FamilyOf(s.Name) == "timing" && s.Contribution() >= negligible
		}
		if !timed {
			t.Errorf("v2=%v: no contributing timing signal: %v", cfg.TimingV2, signalNames(f))
		}
		for _, name := range want {
			found := false
			for _, s := range f.Signals {
				if s.Name == name {
					found = true
					if s.Contribution() < negligible {
						t.Errorf("v2=%v: %s present but negligible (%.3f)", cfg.TimingV2, name, s.Contribution())
					}
				}
			}
			if !found {
				t.Errorf("v2=%v: constellation lacks %s: %v", cfg.TimingV2, name, signalNames(f))
			}
		}
		// cap invariants on the same signal set
		var noPayload []stats.Signal
		for _, s := range f.Signals {
			if !strings.HasPrefix(s.Name, "encoded_payload_in_") && s.Name != "random_payloads" {
				noPayload = append(noPayload, s)
			}
		}
		if !timingPlusRecon(noPayload) {
			t.Errorf("v2=%v: without payload the set must be timing+recon(+URI): %v", cfg.TimingV2, signalNames(f))
		}
		if timingPlusRecon(f.Signals) || timingPlusURIShape(f.Signals) || onlyTiming(f.Signals) {
			t.Errorf("v2=%v: a cap predicate accepts a set with independent payload evidence", cfg.TimingV2)
		}
		if ev := capEvidence(f); ev != "(no cap)" {
			t.Errorf("v2=%v: cap applied to payload-backed finding: %s", cfg.TimingV2, ev)
		}

		// the legitimate lift
		if f.Score <= TimingOnlyMax || stats.Severity(f.Score) != "critical" {
			t.Errorf("v2=%v: payload must lift above %.2f to critical, got %.2f %s", cfg.TimingV2, TimingOnlyMax, f.Score, f.Severity)
		}
		if base.Score > TimingOnlyMax || f.Score <= base.Score {
			t.Errorf("v2=%v: lift %.2f → %.2f (capped base must be ≤ %.2f)", cfg.TimingV2, base.Score, f.Score, TimingOnlyMax)
		}
	}
}
