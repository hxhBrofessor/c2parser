package stats

import (
	"math/rand/v2"
	"testing"
)

func TestLengthResidue(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	gen := func(n int, f func() int) []int {
		out := make([]int, n)
		for i := range out {
			out[i] = f()
		}
		return out
	}
	for _, tc := range []struct {
		name      string
		lens      []int
		ok        bool
		mod, want int
	}{
		{"CBC ≡0 mod 16", gen(60, func() int { return 16 * (2 + r.IntN(40)) }), true, 16, 0},
		{"header ≡4 mod 16", gen(60, func() int { return 4 + 16*(2+r.IntN(40)) }), true, 16, 4},
		{"AEAD-ish ≡12 mod 16", gen(60, func() int { return 12 + 16*(1+r.IntN(40)) }), true, 16, 12},
		{"≡4 mod 8 only", gen(60, func() int { return 4 + 8*(2+r.IntN(80)) }), true, 8, 4},
		{"uniform lengths", gen(200, func() int { return 50 + r.IntN(1500) }), true, 0, 0},
		{"too few messages", gen(7, func() int { return 16 * (2 + r.IntN(40)) }), false, 0, 0},
		{"fixed-size heartbeat", gen(60, func() int { return 64 }), false, 0, 0},
		{"7 distinct lengths", gen(60, func() int { return 16 * (2 + r.IntN(7)) }), false, 0, 0},
		{"low CV", gen(60, func() int { return 16 * (1000 + r.IntN(10)) }), false, 0, 0},
	} {
		got, ok := LengthResidue(tc.lens)
		if ok != tc.ok || ok && (got.Mod != tc.mod || got.Mod != 0 && got.Value != tc.want) {
			t.Errorf("%s: %+v ok=%v, want ok=%v mod %d ≡%d", tc.name, got, ok, tc.ok, tc.mod, tc.want)
		}
	}
}

// FuzzLengthResidue: never panics; a reported class really holds the
// stated share; the guard is respected.
func FuzzLengthResidue(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		var lens []int
		for i := 0; i+1 < len(b); i += 2 {
			lens = append(lens, int(b[i])<<8|int(b[i+1])-1000) // negatives too
		}
		r, ok := LengthResidue(lens)
		if !ok {
			return
		}
		if r.N < ResidueMinMsgs || r.Distinct < ResidueMinDistinct || r.CV < ResidueMinCV && r.CV >= 0 {
			t.Fatalf("guard: %+v", r)
		}
		if r.Mod == 0 {
			return
		}
		n := 0
		for _, l := range lens {
			if ((l%r.Mod)+r.Mod)%r.Mod == r.Value {
				n++
			}
		}
		if float64(n)/float64(len(lens)) != r.Share || r.Share < ResidueMinShare {
			t.Fatalf("share %v vs %d/%d", r.Share, n, len(lens))
		}
	})
}
