package engine

import (
	mrand "math/rand/v2"
	"testing"
	"time"
)

// fleetTLS: the same HTTPS cadence (10 % jitter, one kept-alive session
// each) from n internal clients to one destination.
func fleetTLS(t *testing.T, n int, period float64, cfg Config) *Result {
	s := newSynth(t)
	for k := 0; k < n; k++ {
		r := mrand.New(mrand.NewPCG(uint64(40+k), 7))
		ts := s.now.Add(time.Duration(k*7) * time.Second)
		cl := []string{"10.50.0.11", "10.50.0.12", "10.50.0.13", "10.50.0.14"}[k]
		c := s.tcp(ts, cl, uint16(53100+k), "198.51.100.50", 443)
		ts = c.Send(ts.Add(5*time.Millisecond), true, clientHello("updates.example", []string{"http/1.1"}), 1400)
		ts = c.Send(ts.Add(20*time.Millisecond), false, appData(1400), 1400)
		for i := 0; i < 60; i++ {
			ts = ts.Add(time.Duration(period * (1 - 0.1*r.Float64()) * float64(time.Second)))
			ts = c.Send(ts, true, appData(350+r.IntN(40)), 1400)
			ts = c.Send(ts.Add(40*time.Millisecond), false, appData(200+r.IntN(400)), 1400)
		}
		c.Close(ts.Add(time.Second))
	}
	return s.analyze(cfg)
}

// v9 rev 2 Phase 0.1 gates: the timing-only cap is scoped to fleet
// patterns and scheduler shapes; single-host periodic series keep their
// score (below critical).
func TestTimingOnlyCapScope(t *testing.T) {
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		v := map[bool]string{false: "v1", true: "v2"}[cfg.TimingV2]
		for _, p := range []float64{30, 60} {
			for _, reuse := range []bool{true, false} {
				f, _ := beaconTLS(t, reuse, p, cfg)
				if f == nil || f.Score < 0.6 || f.Score > TimingOnlyMax {
					t.Errorf("%s single-host HTTPS beacon %.0fs keepalive=%v: %v (want 0.6–%.2f)", v, p, reuse, scoreOf(f), TimingOnlyMax)
				}
			}
		}
		for _, p := range []float64{30, 45, 120} {
			f, _ := tinySession(t, p, cfg)
			if f == nil || f.Score < 0.6 {
				t.Errorf("%s single-host ≤100 B bursts %.0fs: %v (want ≥ 0.6)", v, p, scoreOf(f))
			}
		}
		res := fleetTLS(t, 3, 60, cfg)
		for _, f := range res.Findings {
			if f.Server == "198.51.100.50" && f.Score >= 0.4 {
				t.Errorf("%s fleet (3 clients, same cadence) finding %.2f ≥ 0.4: %s", v, f.Score, f.Title)
			}
		}
	}
}

func scoreOf(f *Finding) any {
	if f == nil {
		return "no finding"
	}
	return f.Score
}
