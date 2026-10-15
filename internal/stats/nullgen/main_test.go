package main

import (
	"math"
	"math/rand/v2"
	"testing"
)

func newRand(s uint64) *rand.Rand { return rand.New(rand.NewPCG(s, s)) }

// Determinism: each (family, n) cell has its own PCG stream, so a cell is
// identical across runs regardless of worker scheduling.
func TestCellDeterministic(t *testing.T) {
	a := run(families[0], 0, 19, 300, 7)
	b := run(families[0], 0, 19, 300, 7)
	for _, m := range metrics {
		va, vb := a.vals[m], b.vals[m]
		if len(va) != len(vb) {
			t.Fatalf("%s: %d vs %d values", m, len(va), len(vb))
		}
		for i := range va {
			if va[i] != vb[i] && !(math.IsNaN(va[i]) && math.IsNaN(vb[i])) {
				t.Fatalf("%s[%d]: %v vs %v", m, i, va[i], vb[i])
			}
		}
	}
}

func TestGammaMean(t *testing.T) {
	for _, k := range []float64{0.5, 2, 4} {
		r := newRand(11)
		s := 0.0
		const n = 200000
		for i := 0; i < n; i++ {
			s += gamma(r, k)
		}
		if m := s / n; math.Abs(m-1) > 0.02 {
			t.Errorf("gamma(k=%.1f) mean %.3f, want 1", k, m)
		}
	}
}
