package stats

import "math"

// Decoded-length residue (v11a M2). Block-cipher (CBC) framing makes
// every ciphertext a multiple of the block size; a fixed header or an AEAD
// tag/nonce shifts that by a constant. Over a channel's messages the
// decoded lengths then sit in one residue class mod 16 (or mod 8), where
// free-length plaintext and stream ciphers spread over all classes. The
// class itself (≡0 / ≡4 / ≡12 / uniform) is a v11b profile constant; here
// it is only measured.

// Variability guard: a class is only meaningful when the lengths vary —
// a fixed-size heartbeat is in one class trivially.
const (
	ResidueMinMsgs     = 8
	ResidueMinDistinct = 8
	ResidueMinCV       = 0.05
	ResidueMinShare    = 0.9
)

// Residue is the measured class of a set of message lengths.
type Residue struct {
	Mod      int     `json:"mod"`     // 16 or 8; 0 = no class (uniform / not measurable)
	Value    int     `json:"residue"` // the class: length ≡ Value (mod Mod)
	Share    float64 `json:"share"`   // fraction of messages in the class
	N        int     `json:"n"`
	Distinct int     `json:"distinct"`
	CV       float64 `json:"cv"`
}

// LengthResidue measures the residue class of lengths. ok is false when
// the variability guard fails (not measurable); a measurable set with no
// dominant class returns ok with Mod 0 ("uniform").
func LengthResidue(lengths []int) (Residue, bool) {
	r := Residue{N: len(lengths)}
	if len(lengths) < ResidueMinMsgs {
		return r, false
	}
	seen := map[int]bool{}
	var sum, sq float64
	for _, l := range lengths {
		seen[l] = true
		sum += float64(l)
	}
	mean := sum / float64(len(lengths))
	for _, l := range lengths {
		d := float64(l) - mean
		sq += d * d
	}
	r.Distinct = len(seen)
	if mean > 0 {
		r.CV = math.Sqrt(sq/float64(len(lengths))) / mean
	}
	if r.Distinct < ResidueMinDistinct || r.CV < ResidueMinCV {
		return r, false
	}
	for _, mod := range []int{16, 8} {
		var c [16]int
		for _, l := range lengths {
			c[((l%mod)+mod)%mod]++
		}
		best := 0
		for v := 1; v < mod; v++ {
			if c[v] > c[best] {
				best = v
			}
		}
		if share := float64(c[best]) / float64(len(lengths)); share >= ResidueMinShare {
			r.Mod, r.Value, r.Share = mod, best, share
			return r, true
		}
	}
	return r, true
}
