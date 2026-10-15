package stats

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"math"
	mrand "math/rand/v2"
	"strings"
	"testing"
)

func hist(b []byte) *Histogram { h := &Histogram{}; h.Add(b); return h }

func randBytes(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

func TestNullModelContinuity(t *testing.T) {
	// Monte-Carlo table and asymptotic formula must agree where they meet.
	for _, k := range []int{16, 32, 64, 256} {
		mcMean, _ := NullEntropy(k, 16*k-1)
		asMean, _ := NullEntropy(k, 16*k)
		if math.Abs(mcMean-asMean) > 0.01 {
			t.Errorf("k=%d: MC %.4f vs asymptotic %.4f", k, mcMean, asMean)
		}
	}
	// With n << k the expectation is bounded by log2(n).
	if m, _ := NullEntropy(256, 20); m > math.Log2(20) || m < 3.9 {
		t.Errorf("E[H](256,20)=%.3f, want ~4.2", m)
	}
}

func TestRandomIsRandomAtAnySize(t *testing.T) {
	for _, n := range []int{64, 256, 1116, 4096, 524336} {
		a := Assess(hist(randBytes(n)))
		if a.Alphabet != AlphaBinary {
			t.Fatalf("n=%d alphabet %s", n, a.Alphabet)
		}
		min := 0.95
		if n == 64 {
			min = 0.45 // confidence-limited
		}
		if a.Score < min {
			t.Errorf("n=%d random score %.2f (H=%.2f E=%.2f z=%.1f)", n, a.Score, a.Entropy, a.Expected, a.Z)
		}
	}
}

func TestEncodedCiphertextIsCaught(t *testing.T) {
	raw := randBytes(3000)
	cases := map[string]struct {
		s     string
		alpha Alphabet
	}{
		"base64": {base64.StdEncoding.EncodeToString(raw), AlphaBase64},
		"b64url": {base64.RawURLEncoding.EncodeToString(raw), AlphaBase64},
		"hex":    {hex.EncodeToString(raw), AlphaHex},
		"base32": {strings.ToLower(base32.StdEncoding.EncodeToString(raw)), AlphaBase32},
	}
	for name, c := range cases {
		a := Assess(hist([]byte(c.s)))
		if a.Alphabet != c.alpha {
			t.Errorf("%s: alphabet %s want %s", name, a.Alphabet, c.alpha)
		}
		// The old fixed 7.5/7.8 threshold misses every one of these.
		if a.Shannon > 7.0 {
			t.Errorf("%s: shannon %.2f unexpectedly high", name, a.Shannon)
		}
		if a.Score < 0.95 {
			t.Errorf("%s: score %.2f (H=%.3f E=%.3f z=%.1f)", name, a.Score, a.Entropy, a.Expected, a.Z)
		}
	}
}

func TestStructuredDataIsNotRandom(t *testing.T) {
	havocCheckin := []byte{0, 0, 0, 0x10, 0xde, 0xad, 0xbe, 0xef, 0x73, 0xb2, 0xe9, 0xb0, 0, 0, 0, 1, 0, 0, 0, 0}
	text := []byte(strings.Repeat(`{"user":"alice","action":"login","ok":true,"ts":1711382033} `, 40))
	html := []byte(strings.Repeat("<div class=\"row\"><span>Hello world, this is a page.</span></div>\n", 60))
	for name, b := range map[string][]byte{"havoc20": havocCheckin, "json": text, "html": html} {
		if a := Assess(hist(b)); a.Score > 0.1 {
			t.Errorf("%s: score %.2f (alpha %s H=%.2f E=%.2f z=%.1f)", name, a.Score, a.Alphabet, a.Entropy, a.Expected, a.Z)
		}
	}
}

func TestBeaconSeparatesTimerFromPoisson(t *testing.T) {
	r := mrand.New(mrand.NewPCG(1, 2))
	var tt, ts, pt, ps []float64
	now, pnow := 0.0, 0.0
	for i := 0; i < 200; i++ {
		now += 2.0 * (1 + 0.1*(r.Float64()*2-1)) // 2s sleep, ±10% jitter
		tt = append(tt, now)
		ts = append(ts, 20)
		pnow += r.ExpFloat64() * 2 // Poisson, same mean rate
		pt = append(pt, pnow)
		ps = append(ps, float64(200+r.IntN(4000)))
	}
	b, _ := ScoreBeacon(tt, ts, DefaultBeaconParams)
	p, _ := ScoreBeacon(pt, ps, DefaultBeaconParams)
	if b.Score < 0.85 {
		t.Errorf("timer beacon score %.2f, want >= 0.85 (%+v)", b.Score, b)
	}
	if p.Score > 0.45 {
		t.Errorf("poisson score %.2f, want <= 0.45 (%+v)", p.Score, p)
	}
	if _, ok := ScoreBeacon(tt[:5], ts[:5], DefaultBeaconParams); ok {
		t.Error("5 events should not score")
	}
}

func TestNoisyOR(t *testing.T) {
	s := []Signal{{Score: 1, Weight: .5}, {Score: 1, Weight: .5}, {Score: 0, Weight: 1}}
	if got := NoisyOR(s); math.Abs(got-0.75) > 1e-9 {
		t.Errorf("got %.3f want .75", got)
	}
}

func TestLettersAlphabetSeparatesDGAFromWords(t *testing.T) {
	r := mrand.New(mrand.NewPCG(9, 9))
	var dga []byte
	for i := 0; i < 600; i++ {
		dga = append(dga, byte('a'+r.IntN(26)))
	}
	words := []byte(strings.Repeat("microsoftofficeupdatewindowsgooglemailstoragecontent", 12))
	ad, aw := Assess(hist(dga)), Assess(hist(words))
	if ad.Alphabet != AlphaLetter || aw.Alphabet != AlphaLetter {
		t.Fatalf("alphabets %s %s", ad.Alphabet, aw.Alphabet)
	}
	if ad.Score < 0.9 || aw.Score > 0.1 {
		t.Errorf("dga %.2f (want ≥.9) words %.2f (want ≤.1)", ad.Score, aw.Score)
	}
}

// Netskope's example: Cobalt Strike 60 s sleep with ±15% jitter (51–69 s),
// with task traffic interleaved and a few missed check-ins.
func TestBeaconCobaltStrikeJitterWithNoise(t *testing.T) {
	r := mrand.New(mrand.NewPCG(5, 6))
	var ts, sz []float64
	now := 0.0
	for i := 0; i < 120; i++ {
		step := 60 * (1 + 0.15*(r.Float64()*2-1))
		if r.IntN(15) == 0 {
			step += 60 // missed check-in
		}
		now += step
		ts = append(ts, now)
		sz = append(sz, 48)
		if r.IntN(8) == 0 { // operator task: extra event shortly after
			ts = append(ts, now+1+r.Float64()*3)
			sz = append(sz, float64(500+r.IntN(5000)))
		}
	}
	b, ok := ScoreBeacon(ts, sz, DefaultBeaconParams)
	if !ok || b.Score < 0.75 {
		t.Errorf("CS 60s±15%% with noise scored %.2f (window %.2f disp %.2f): %+v", b.Score, b.TSWindow, b.TSDisp, b)
	}
	if b.MedianSec < 51 || b.MedianSec > 69 {
		t.Errorf("median %.1f outside 51–69", b.MedianSec)
	}
}

func TestAlphabetSupportDetection(t *testing.T) {
	r := mrand.New(mrand.NewPCG(21, 22))
	gen := func(alpha string, n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = alpha[r.IntN(len(alpha))]
		}
		return b
	}
	cases := []struct {
		alpha string
		want  Alphabet
	}{
		{"ab1c2d3e4f5g6h7j8k9m0npqrtuvwxyz", AlphaCustom32}, // Sliver DNS base32
		{"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", AlphaBase58},
		{"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", AlphaBase62},
		{"abcdefghijklmnop", AlphaNetbios},
	}
	for _, c := range cases {
		a := AssessBytes(gen(c.alpha, 4000))
		if a.Alphabet != c.want || a.Score < 0.95 {
			t.Errorf("%s: got %s score %.2f (H=%.2f E=%.2f)", c.want, a.Alphabet, a.Score, a.Entropy, a.Expected)
		}
	}
	// Small samples must not be "refined" (not enough draws to see every symbol).
	if a := AssessBytes(gen("ab1c2d3e4f5g6h7j8k9m0npqrtuvwxyz", 200)); a.Alphabet == AlphaCustom32 {
		t.Error("refined on too small a sample")
	}
}
