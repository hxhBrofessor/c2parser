package engine

import (
	"fmt"
	mrand "math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/layers"

	"c2parser/internal/stats"
	sy "c2parser/internal/synth"
)

// R-01: the F07 query-shape cap may only act on *measured* name reuse
// (dnsNameReuse), never on a missing novelty measurement. Below 20 logical
// queries name_cardinality_ratio is not emitted, so high-novelty short
// channels used to be capped; moderate novelty (ratio ≥ 0.4) is not reuse.

// dnsShapeChannel: one client, a 7 s cadence, cacheable A answers (TTL 300),
// labels × labelLen-symbol names from the custom32 alphabet. unique ≤ logical
// distinct names are cycled; each logical query is sent 1+retries times
// within the 3 s retry window, so logical (not raw) queries stay as given.
func dnsShapeChannel(t *testing.T, logical, unique, labels, labelLen, retries int, cfg Config) *Result {
	t.Helper()
	s := newSynth(t)
	r := mrand.New(mrand.NewPCG(1701, uint64(logical<<20|unique<<8|labelLen)))
	names := make([]string, unique)
	for i := range names {
		ls := make([]string, labels)
		for l := range ls {
			b := make([]byte, labelLen)
			for j := range b {
				b[j] = sy.DNSAlphaCustom32[r.IntN(32)]
			}
			ls[l] = string(b)
		}
		names[i] = strings.Join(ls, ".") + ".shape.example"
	}
	id := uint16(1)
	for k := 0; k < logical; k++ {
		name := names[k%unique]
		for try := 0; try <= retries; try++ {
			ts := s.now.Add(time.Duration(k)*7*time.Second + time.Duration(try)*200*time.Millisecond)
			s.dnsQuery(ts, "10.0.0.90", "10.0.0.53", name, layers.DNSTypeA, id)
			rr := layers.DNSResourceRecord{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 300, IP: []byte{192, 0, 2, 1}}
			s.dnsResp(ts.Add(15*time.Millisecond), "10.0.0.90", "10.0.0.53", name, layers.DNSTypeA, id, layers.DNSResponseCodeNoErr, []layers.DNSResourceRecord{rr})
			id++
		}
	}
	return s.analyze(cfg)
}

type shapeRun struct {
	score  float64
	sev    string
	capped bool
	sigs   string
	timing float64 // noisy-OR of the timing-family signals alone
	found  bool
}

func runShape(t *testing.T, guard bool, logical, unique, labelLen, retries int, cfg Config) shapeRun {
	t.Helper()
	saved := dnsShapeCap
	defer func() { dnsShapeCap = saved }()
	dnsShapeCap = guard
	f := findBy(dnsShapeChannel(t, logical, unique, 3, labelLen, retries, cfg), CatDNS, "shape.example")
	if f == nil {
		return shapeRun{}
	}
	var sig []string
	var timing []stats.Signal
	for _, s := range f.Signals {
		if s.Contribution() >= negligible {
			sig = append(sig, fmt.Sprintf("%s=%.3f", s.Name, s.Contribution()))
		}
		if stats.FamilyOf(s.Name) == "timing" {
			timing = append(timing, s)
		}
	}
	return shapeRun{f.Score, f.Severity, strings.Contains(capEvidence(f), "correlated DNS query-name"), strings.Join(sig, " "), stats.NoisyOR(timing), true}
}

func engineName(cfg Config) string {
	if cfg.TimingV2 {
		return "v2"
	}
	return "v1"
}

// High novelty at 19/20/21 logical queries: never shape-capped, identical to
// the guard-off score and at least high. Low novelty (two names cycled) is
// measured reuse at every count and is capped the same way on both sides of
// the 20-query novelty threshold.
func TestDNSShapeCapCardinalityBoundary(t *testing.T) {
	for _, n := range []int{19, 20, 21} {
		for _, cfg := range []Config{{}, {TimingV2: true}} {
			for _, nov := range []struct {
				name   string
				unique int
			}{{"high", n}, {"low", 2}} {
				on := runShape(t, true, n, nov.unique, 63, 0, cfg)
				off := runShape(t, false, n, nov.unique, 63, 0, cfg)
				t.Logf("logical=%d novelty=%s %s: guard on %.2f %s capped=%v | guard off %.2f %s | %s", n, nov.name, engineName(cfg), on.score, on.sev, on.capped, off.score, off.sev, on.sigs)
				if !on.found || !off.found {
					t.Fatalf("logical=%d novelty=%s %s: missing finding", n, nov.name, engineName(cfg))
				}
				switch {
				case nov.name == "high":
					if on.capped || on.score != off.score || on.score < .65 {
						t.Errorf("logical=%d high novelty %s: %.2f capped=%v, want guard-off %.2f and ≥ 0.65", n, engineName(cfg), on.score, on.capped, off.score)
					}
				default:
					if off.score > TimingOnlyCap && (!on.capped || on.score != TimingOnlyCap) {
						t.Errorf("logical=%d low novelty %s: measured reuse must cap (%.2f capped=%v)", n, engineName(cfg), on.score, on.capped)
					}
				}
			}
		}
	}
}

// dnsNameReuse is a direct count: fewer than 0.4 distinct names per logical
// query; nothing when there are no logical queries or the distinct-name set
// is saturated (a huge all-unique tunnel would otherwise look like reuse).
func TestDNSNameReuse(t *testing.T) {
	for _, c := range []struct {
		logical, unique int
		want            bool
	}{
		{19, 19, false}, {19, 2, true}, {19, 7, true}, {19, 8, false},
		{20, 7, true}, {20, 8, false}, {300, 22, true}, {200, 90, false},
		{10, 3, true}, {0, 0, false}, {3 * maxUniqueSubs, maxUniqueSubs, false},
	} {
		if got := dnsNameReuse(c.logical, c.unique); got != c.want {
			t.Errorf("dnsNameReuse(%d, %d) = %v, want %v", c.logical, c.unique, got, c.want)
		}
	}
}

// Retries collapse to logical queries: 19 logical sent three times each is
// still 19 logical, so cardinality stays unmeasured and the cap stays off.
func TestDNSShapeCapRetriesDoNotMeasure(t *testing.T) {
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		on := runShape(t, true, 19, 19, 63, 2, cfg)
		off := runShape(t, false, 19, 19, 63, 2, cfg)
		if !on.found || on.capped || on.score != off.score || on.score < .65 {
			t.Errorf("%s: 19 logical ×3 retries %.2f capped=%v (guard off %.2f)", engineName(cfg), on.score, on.capped, off.score)
		}
	}
}

// Moderate novelty (ratio 0.45, below name_cardinality_ratio's contribution
// floor but not reuse) and a large encoded volume: not shape-capped.
func TestDNSShapeCapModerateNovelty(t *testing.T) {
	for _, c := range []struct{ logical, unique int }{{200, 90}, {1000, 450}} {
		for _, cfg := range []Config{{}, {TimingV2: true}} {
			on := runShape(t, true, c.logical, c.unique, 63, 0, cfg)
			off := runShape(t, false, c.logical, c.unique, 63, 0, cfg)
			if !on.found || on.capped || on.score != off.score || on.score < .85 {
				t.Errorf("%d/%d %s: %.2f capped=%v, want guard-off %.2f critical", c.logical, c.unique, engineName(cfg), on.score, on.capped, off.score)
			}
		}
	}
}

// Monotonicity: the same channel with long encoded-looking names never
// scores below the same channel with short names, and wherever the shape cap
// acts the timing evidence alone stays ≤ 0.39 — adding name-shape evidence
// can never lower a finding below what its other evidence earns.
func TestDNSShapeCapMonotonic(t *testing.T) {
	for _, c := range []struct{ logical, unique int }{{15, 15}, {19, 19}, {19, 2}, {19, 7}, {20, 20}, {20, 2}, {21, 21}, {21, 2}, {40, 15}, {200, 90}, {300, 22}, {1000, 450}} {
		for _, cfg := range []Config{{}, {TimingV2: true}} {
			short := runShape(t, true, c.logical, c.unique, 8, 0, cfg)
			long := runShape(t, true, c.logical, c.unique, 63, 0, cfg)
			t.Logf("%d/%d %s: 8-char %.2f %s, 63-char %.2f %s capped=%v", c.logical, c.unique, engineName(cfg), short.score, short.sev, long.score, long.sev, long.capped)
			if long.score < short.score {
				t.Errorf("%d/%d %s: long names %.2f < short names %.2f", c.logical, c.unique, engineName(cfg), long.score, short.score)
			}
			if long.capped && long.timing > TimingOnlyCap {
				t.Errorf("%d/%d %s: capped at %.2f below its timing evidence %.2f", c.logical, c.unique, engineName(cfg), long.score, long.timing)
			}
		}
	}
}
