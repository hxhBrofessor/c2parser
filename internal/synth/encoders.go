package synth

import (
	"math/rand/v2"
	"strings"
	"sync"
)

// Encoders for v11a carrier shapes. These are our own models of the
// encoding *classes* (no framework code): base58 with the Bitcoin
// alphabet, and a word-run encoding where every byte becomes one
// word whose case-sensitive letter sum ≡ the byte (mod 256) — the
// SumWord rule of the supplied Sliver snapshot (util/encoders/english.go).
// Words are our own syllable strings, mostly capitalised like the
// snapshot's dictionaries; no upstream word list is used. The engine's
// word-run decoder is dictionary-free (internal/engine/carriers.go).

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Base58 encodes b (big-endian big number; leading zero bytes → '1').
func Base58(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	// little-endian base-58 digits
	var digits []byte
	for _, c := range b[zeros:] {
		carry := int(c)
		for j := range digits {
			carry += int(digits[j]) << 8
			digits[j] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, byte(carry%58))
			carry /= 58
		}
	}
	out := make([]byte, zeros+len(digits))
	for i := 0; i < zeros; i++ {
		out[i] = '1'
	}
	for i, d := range digits {
		out[len(out)-1-i] = base58Alphabet[d]
	}
	return string(out)
}

var (
	wordsOnce  sync.Once
	wordBucket [256][]string
)

// wordTable builds, deterministically, ≥ 4 pseudo-words of 3–9 letters
// for every residue of the letter sum mod 256. The words are syllable
// strings, not a framework's dictionary.
func wordTable() *[256][]string {
	wordsOnce.Do(func() {
		r := rand.New(rand.NewPCG(0x77, 0x6f72647321))
		cons, vow := "bcdfghklmnprstvwz", "aeiou"
		for missing := 256; missing > 0; {
			var sb strings.Builder
			n := 2 + r.IntN(4) // syllables
			for i := 0; i < n; i++ {
				sb.WriteByte(cons[r.IntN(len(cons))])
				sb.WriteByte(vow[r.IntN(len(vow))])
			}
			if r.IntN(2) == 0 {
				sb.WriteByte(cons[r.IntN(len(cons))])
			}
			w := sb.String()
			if r.IntN(4) != 0 { // capitalised, like both dictionaries in the Sliver snapshot
				w = strings.ToUpper(w[:1]) + w[1:]
			}
			s := byte(letterSum(w))
			if len(wordBucket[s]) < 4 {
				wordBucket[s] = append(wordBucket[s], w)
				if len(wordBucket[s]) == 4 {
					missing--
				}
			}
		}
	})
	return &wordBucket
}

func letterSum(w string) int {
	s := 0
	for i := 0; i < len(w); i++ {
		s += int(w[i])
	}
	return s
}

// Words encodes b as space-separated words, one per byte. The word for a
// byte is chosen by position, so the output is a pure function of b.
func Words(b []byte) string {
	t := wordTable()
	ws := make([]string, len(b))
	for i, c := range b {
		cand := t[c]
		ws[i] = cand[(i*7+int(c))%len(cand)]
	}
	return strings.Join(ws, " ")
}
