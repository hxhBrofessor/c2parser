package stats

import (
	"encoding/json"
	"math/rand/v2"
	"testing"
)

// Metamorphic invariants (stress doc §G): shifting every timestamp changes
// nothing; scaling every gap by k leaves unit-free metrics unchanged.
func TestTimingMetamorphic(t *testing.T) {
	r := rand.New(rand.NewPCG(21, 21))
	times := series(gapsOf(80, func() float64 { return 60 * (1 - 0.3*r.Float64()) }))
	base := AnalyzeTiming(times, TimingParams{})
	shifted := make([]float64, len(times))
	scaled := make([]float64, len(times))
	for i, x := range times {
		shifted[i] = x + 86400*365
		scaled[i] = x * 7.5
	}
	js := func(t Timing) string { b, _ := json.Marshal(t); return string(b) }
	if a, b := js(base), js(AnalyzeTiming(shifted, TimingParams{})); a != b {
		t.Errorf("time shift changed timing:\n%s\n%s", a, b)
	}
	sc := AnalyzeTiming(scaled, TimingParams{})
	type unitFree struct {
		CV, An, Rh, Spread *float64
		Pol                string
		Idle, Missed       int
	}
	u := func(t Timing) string {
		b, _ := json.Marshal(unitFree{t.CV, t.An, t.Rh, t.Spread, t.Polarity, t.IdleGaps, t.MissedBeats})
		return string(b)
	}
	if a, b := u(base), u(sc); a != b {
		t.Errorf("gap scaling changed unit-free metrics:\n%s\n%s", a, b)
	}
	s1, _ := base.DispersionEvidence()
	s2, _ := sc.DispersionEvidence()
	if s1 != s2 {
		t.Errorf("gap scaling changed dispersion evidence %.3f → %.3f", s1, s2)
	}
}
