// Package stats holds the detection math: size- and alphabet-aware
// randomness scoring, robust statistics, beacon scoring and evidence
// combination. Nothing in here knows about packets.
package stats

import (
	"math"
	"math/rand/v2"
	"sort"
	"sync"
)

// Histogram is a streaming byte-frequency counter. Feeding it chunk by chunk
// gives exactly the same result as feeding the whole body at once, so bodies
// never have to be held in memory.
type Histogram struct {
	Counts [256]uint64
	N      uint64
}

// Add folds b into the histogram.
func (h *Histogram) Add(b []byte) {
	for _, c := range b {
		h.Counts[c]++
	}
	h.N += uint64(len(b))
}

// Merge adds another histogram into h.
func (h *Histogram) Merge(o *Histogram) {
	for i := range h.Counts {
		h.Counts[i] += o.Counts[i]
	}
	h.N += o.N
}

// Shannon returns the plain Shannon entropy in bits per byte (0..8).
func (h *Histogram) Shannon() float64 {
	return entropyOf(h.Counts[:], h.N)
}

func entropyOf(counts []uint64, n uint64) float64 {
	if n == 0 {
		return 0
	}
	fn := float64(n)
	e := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / fn
		e -= p * math.Log2(p)
	}
	return e
}

// Alphabet is the symbol set a payload appears to be drawn from.
type Alphabet string

const (
	AlphaEmpty    Alphabet = "empty"
	AlphaHex      Alphabet = "hex"      // 16 symbols, case-folded
	AlphaLetter   Alphabet = "letters"  // 26 symbols, case-folded (DGA labels, words)
	AlphaBase32   Alphabet = "base32"   // 32 symbols, case-folded, '=' ignored
	AlphaAlnum    Alphabet = "alnum"    // 36 symbols (DNS-style a-z0-9), '-' ignored
	AlphaBase64   Alphabet = "base64"   // 64 symbols (std or url-safe), '=' ignored
	AlphaText     Alphabet = "text"     // printable ASCII, 95 symbols
	AlphaNetbios  Alphabet = "netbios"  // 16 symbols a-p / A-P (Cobalt Strike & Mythic httpx "netbios" transform)
	AlphaCustom32 Alphabet = "custom32" // 32 distinct alnum symbols, e.g. Sliver's base32 alphabet
	AlphaBase58   Alphabet = "base58"   // 58 distinct case-sensitive alnum symbols
	AlphaBase62   Alphabet = "base62"   // 62 distinct case-sensitive alnum symbols
	AlphaBinary   Alphabet = "binary"   // 256 symbols
)

// Size returns the number of distinct symbols the alphabet allows.
func (a Alphabet) Size() int {
	switch a {
	case AlphaHex, AlphaNetbios:
		return 16
	case AlphaCustom32:
		return 32
	case AlphaBase58:
		return 58
	case AlphaBase62:
		return 62
	case AlphaLetter:
		return 26
	case AlphaBase32:
		return 32
	case AlphaAlnum:
		return 36
	case AlphaBase64:
		return 64
	case AlphaText:
		return 95
	case AlphaBinary:
		return 256
	}
	return 1
}

func isHex(c byte) bool   { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }
func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isLower(c byte) bool { return c >= 'a' && c <= 'z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isB32(c byte) bool   { return isUpper(c) || isLower(c) || c >= '2' && c <= '7' || c == '=' }
func isAlnum(c byte) bool { return isUpper(c) || isLower(c) || isDigit(c) || c == '-' }
func isB64(c byte) bool {
	return isUpper(c) || isLower(c) || isDigit(c) || c == '+' || c == '/' || c == '-' || c == '_' || c == '='
}
func isText(c byte) bool { return c == '\t' || c == '\n' || c == '\r' || c >= 0x20 && c <= 0x7e }

// Classify picks the narrowest alphabet that contains every byte present.
func (h *Histogram) Classify() Alphabet {
	if h.N == 0 {
		return AlphaEmpty
	}
	hex, let, b32, aln, b64, txt := true, true, true, true, true, true
	nbl, nbu := true, true
	upper, lower := false, false
	for i, c := range h.Counts {
		if c == 0 {
			continue
		}
		b := byte(i)
		hex = hex && isHex(b)
		nbl = nbl && b >= 'a' && b <= 'p'
		upper = upper || isUpper(b)
		lower = lower || isLower(b)
		nbu = nbu && b >= 'A' && b <= 'P'
		let = let && (isUpper(b) || isLower(b))
		b32 = b32 && isB32(b)
		aln = aln && isAlnum(b)
		b64 = b64 && isB64(b)
		txt = txt && isText(b)
	}
	switch {
	case hex:
		return AlphaHex
	case (nbl || nbu) && h.N >= 32:
		return AlphaNetbios
	case let:
		return AlphaLetter
	case (b32 || aln) && upper && lower:
		// Mixed case in an alnum-only payload means a case-sensitive
		// encoding (base58/base62/base64 without symbols), not DNS-style
		// alnum; score it against the 64-symbol set (refined by support).
		return AlphaBase64
	case b32:
		return AlphaBase32
	case aln:
		return AlphaAlnum
	case b64:
		return AlphaBase64
	case txt:
		return AlphaText
	}
	return AlphaBinary
}

// symbolCounts returns the histogram re-binned for the alphabet: case is
// folded where the encoding is case-insensitive and padding is dropped.
// buf is caller-provided scratch so a per-call 2 KB table doesn't reach
// the heap (v9c 3.3).
func (h *Histogram) symbolCounts(a Alphabet, buf *[256]uint64) ([]uint64, uint64) {
	switch a {
	case AlphaHex, AlphaLetter, AlphaBase32, AlphaAlnum, AlphaNetbios, AlphaCustom32:
		folded := buf
		*folded = [256]uint64{}
		var n uint64
		for i, c := range h.Counts {
			b := byte(i)
			if b == '=' || b == '-' {
				continue
			}
			if isUpper(b) {
				b += 'a' - 'A'
			}
			folded[b] += c
			n += c
		}
		return folded[:], n
	case AlphaBase64, AlphaBase58, AlphaBase62:
		*buf = [256]uint64{}
		out := buf[:]
		var n uint64
		for i, c := range h.Counts {
			if byte(i) == '=' {
				continue
			}
			out[i] = c
			n += c
		}
		return out, n
	}
	return h.Counts[:], h.N
}

// Assessment says how close a payload is to "indistinguishable from random"
// for its own alphabet and length.
type Assessment struct {
	N          int      `json:"n"`
	Alphabet   Alphabet `json:"alphabet"`
	Shannon    float64  `json:"shannon"`    // raw bits/byte, 0..8 (legacy metric)
	Entropy    float64  `json:"entropy"`    // bits/symbol in the detected alphabet
	Expected   float64  `json:"expected"`   // E[H] for truly random data of this length & alphabet
	StdDev     float64  `json:"stddev"`     // sd[H] under the same null model
	Z          float64  `json:"z"`          // (H - E[H]) / sd
	Ratio      float64  `json:"ratio"`      // H / E[H]
	Confidence float64  `json:"confidence"` // 0..1, grows with sample size
	Score      float64  `json:"score"`      // 0..1, "looks encrypted/compressed"
}

// Assess scores a histogram. The key idea: never compare raw entropy to a
// fixed number. A 20-byte random token can only reach ~4.2 bits, and base64
// of ciphertext tops out at 6 bits. Instead, compare the observed entropy to
// what *random data of the same length and alphabet* would produce.
func Assess(h *Histogram) Assessment {
	a := Assessment{N: int(h.N), Alphabet: h.Classify(), Shannon: h.Shannon()}
	if h.N < 2 {
		return a
	}
	var buf [256]uint64
	counts, n := h.symbolCounts(a.Alphabet, &buf)
	a.Alphabet = refineBySupport(a.Alphabet, counts, n)
	a.Entropy = entropyOf(counts, n)
	k := a.Alphabet.Size()
	mean, sd := NullEntropy(k, int(n))
	a.Expected, a.StdDev = mean, sd
	if mean > 0 {
		a.Ratio = a.Entropy / mean
	}
	if sd < 1e-9 {
		sd = 1e-9
	}
	a.Z = (a.Entropy - mean) / sd

	// z-score term: within ~3 sd of random is "random"; -10 sd is clearly not.
	zs := clamp01(1 - (-a.Z-3)/7)
	if a.Z >= -3 {
		zs = 1
	}
	// ratio term: rescues very large bodies whose sd is tiny, where a few
	// plaintext framing bytes would otherwise push z far negative.
	rs := clamp01((a.Ratio - 0.90) / 0.08)
	// confidence: 16 symbols -> 0, 256+ symbols -> 1
	a.Confidence = clamp01((math.Log2(float64(n)) - 4) / 4)
	a.Score = math.Max(zs, rs) * a.Confidence
	if a.Alphabet == AlphaText {
		// Free-form printable text is almost never uniformly random; only a
		// custom 95-symbol encoding would be. Halve the weight.
		a.Score *= 0.5
	}
	return a
}

// refineBySupport recognises encodings by how many distinct symbols they
// actually use once the sample is large enough that every symbol of a
// uniform source would have appeared (n ≥ 20·d ⇒ P(miss) < d·e^-20).
// Sliver's DNS base32 uses 32 letters+digits (not RFC 4648), which would
// otherwise be scored against a 36-symbol alnum null and look less random.
func refineBySupport(a Alphabet, counts []uint64, n uint64) Alphabet {
	d := 0
	for _, c := range counts {
		if c > 0 {
			d++
		}
	}
	if n < uint64(20*d) {
		return a
	}
	switch {
	case a == AlphaAlnum && d == 32:
		return AlphaCustom32
	case a == AlphaBase64 && d == 58:
		return AlphaBase58
	case a == AlphaBase64 && d == 62:
		return AlphaBase62
	}
	return a
}

// AssessBytes is Assess for a single buffer.
func AssessBytes(b []byte) Assessment {
	h := &Histogram{}
	h.Add(b)
	return Assess(h)
}

// ------------------------------------------------------------ null model

type nullPoint struct {
	n        int
	mean, sd float64
}

var (
	nullMu    sync.Mutex
	nullCache = map[int][]nullPoint{}
)

// NullEntropy returns the mean and standard deviation of the plug-in Shannon
// entropy estimate for n symbols drawn uniformly from k. Small n uses a
// deterministic Monte-Carlo table (computed once per k); large n uses the
// asymptotic result 2n·ln2·(log2k − H) ~ χ²(k−1).
func NullEntropy(k, n int) (mean, sd float64) {
	if n <= 1 || k <= 1 {
		return 0, 0
	}
	if n >= 16*k {
		return asymptotic(k, n)
	}
	grid := nullGrid(k)
	ln := math.Log(float64(n))
	i := sort.Search(len(grid), func(i int) bool { return grid[i].n >= n })
	if i < len(grid) && grid[i].n == n {
		return grid[i].mean, grid[i].sd
	}
	if i == 0 {
		return grid[0].mean, grid[0].sd
	}
	var hi nullPoint
	if i >= len(grid) {
		m, s := asymptotic(k, 16*k)
		hi = nullPoint{16 * k, m, s}
	} else {
		hi = grid[i]
	}
	lo := grid[i-1]
	t := (ln - math.Log(float64(lo.n))) / (math.Log(float64(hi.n)) - math.Log(float64(lo.n)))
	return lo.mean + t*(hi.mean-lo.mean), lo.sd + t*(hi.sd-lo.sd)
}

func asymptotic(k, n int) (float64, float64) {
	d := 2 * float64(n) * math.Ln2
	return math.Log2(float64(k)) - float64(k-1)/d, math.Sqrt(2*float64(k-1)) / d
}

func nullGrid(k int) []nullPoint {
	nullMu.Lock()
	defer nullMu.Unlock()
	if g, ok := nullCache[k]; ok {
		return g
	}
	const trials = 400
	rng := rand.New(rand.NewPCG(uint64(k), 0x9e3779b97f4a7c15))
	counts := make([]uint64, k)
	var g []nullPoint
	for n := 2; n < 16*k; n = nextGrid(n) {
		var m, m2 float64
		for t := 1; t <= trials; t++ {
			clear(counts)
			for j := 0; j < n; j++ {
				counts[rng.IntN(k)]++
			}
			e := entropyOf(counts, uint64(n))
			d := e - m
			m += d / float64(t)
			m2 += d * (e - m)
		}
		g = append(g, nullPoint{n, m, math.Sqrt(m2 / (trials - 1))})
	}
	nullCache[k] = g
	return g
}

// nextGrid steps roughly geometrically (×1.25) so interpolation error in
// log(n) stays well under the Monte-Carlo noise.
func nextGrid(n int) int {
	nx := n * 5 / 4
	if nx <= n {
		nx = n + 1
	}
	return nx
}

func clamp01(x float64) float64 {
	if x < 0 || math.IsNaN(x) {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

// Clamp01 is exported for callers building their own scores.
func Clamp01(x float64) float64 { return clamp01(x) }
