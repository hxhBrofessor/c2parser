package stats

import (
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"sort"
	"testing"
)

// Stress grid (from the v8a stress-testing prototype, see
// claude/c2parser-stress-testing.md). TestStressGates is the CI gate;
// TestStressReport prints the full grid when C2PARSER_STRESS_REPORT is set.

type gen func(r *rand.Rand, n int) []float64

func beaconGen(pol string, S, j float64) gen {
	return func(r *rand.Rand, n int) []float64 {
		t := []float64{r.Float64() * S}
		for len(t) < n {
			var g float64
			switch pol {
			case "shorten":
				g = S * (1 - j*r.Float64())
			case "lengthen":
				g = S + j*S*r.Float64()
			case "symmetric":
				g = S * (1 + j*(2*r.Float64()-1))
			case "anchored":
				k := float64(len(t))
				t = append(t, k*S+j*S*r.Float64())
				continue
			}
			t = append(t, t[len(t)-1]+math.Max(g, 0.05))
		}
		sort.Float64s(t)
		return t
	}
}

type artifact func(r *rand.Rand, t []float64, S float64) []float64

var artifacts = []struct {
	name string
	f    artifact
}{
	{"clean", func(r *rand.Rand, t []float64, S float64) []float64 { return t }},
	{"miss20%", func(r *rand.Rand, t []float64, S float64) []float64 {
		var o []float64
		for _, x := range t {
			if r.Float64() > 0.2 {
				o = append(o, x)
			}
		}
		return o
	}},
	{"tasking25%", func(r *rand.Rand, t []float64, S float64) []float64 {
		o := append([]float64(nil), t...)
		for _, x := range t {
			if r.Float64() < 0.25 {
				y := x
				for k := 0; k < 3; k++ {
					y += 0.2 + 1.8*r.Float64()
					o = append(o, y)
				}
			}
		}
		sort.Float64s(o)
		return o
	}},
	{"stall5%", func(r *rand.Rand, t []float64, S float64) []float64 {
		o := make([]float64, len(t))
		shift := 0.0
		for i, x := range t {
			if r.Float64() < 0.05 {
				shift += S * (0.5 + 2*r.Float64()) // network stall delays everything after it
			}
			o[i] = x + shift
		}
		return o
	}},
	{"quant1s", func(r *rand.Rand, t []float64, S float64) []float64 {
		o := make([]float64, len(t))
		for i, x := range t {
			o[i] = math.Floor(x)
		}
		return o
	}},
	{"2implants", func(r *rand.Rand, t []float64, S float64) []float64 {
		// a second identical implant on the same host/destination, random phase
		off := r.Float64() * S
		o := append([]float64(nil), t...)
		for _, x := range t[:len(t)/2] {
			o = append(o, x+off)
		}
		sort.Float64s(o)
		return o
	}},
}

func nullGen(name string) gen {
	return func(r *rand.Rand, n int) []float64 {
		t := []float64{0}
		for len(t) < n {
			var g float64
			switch name {
			case "poisson":
				g = r.ExpFloat64() * 60
			case "gamma0.5":
				g = gammaS(r, 0.5) * 120
			case "gamma4":
				g = gammaS(r, 4) * 15
			case "browsing":
				if r.Float64() < 0.8 {
					g = math.Exp(r.NormFloat64()*1.0) * 0.5
				} else {
					g = math.Exp(r.NormFloat64()*1.2) * 120
				}
			case "jamf15m±5":
				g = 900 + 600*(r.Float64()-0.5)
			case "gpo90+0-30":
				g = 5400 + 1800*r.Float64()
			}
			t = append(t, t[len(t)-1]+g)
		}
		return t
	}
}

func gammaS(r *rand.Rand, k float64) float64 { // Marsaglia–Tsang
	if k < 1 {
		return gammaS(r, k+1) * math.Pow(r.Float64(), 1/k)
	}
	d := k - 1.0/3
	c := 1 / math.Sqrt(9*d)
	for {
		x := r.NormFloat64()
		v := 1 + c*x
		if v <= 0 {
			continue
		}
		v = v * v * v
		u := r.Float64()
		if math.Log(u) < 0.5*x*x+d-d*v+d*math.Log(v) {
			return d * v
		}
	}
}

func sizes(r *rand.Rand, n int, c2 bool) []float64 {
	s := make([]float64, n)
	for i := range s {
		if c2 {
			s[i] = 300 + float64(r.IntN(8))
		} else {
			s[i] = math.Exp(6 + 1.5*r.NormFloat64())
		}
	}
	return s
}

func detect(t []float64, c2 bool, r *rand.Rand) (v1, v2 bool, refused bool) {
	sz := sizes(r, len(t), c2)
	b, ok := ScoreBeacon(t, sz, DefaultBeaconParams)
	v1 = ok && b.Score >= 0.55
	tm := AnalyzeTiming(t, TimingParams{Sizes: sz})
	s, _ := tm.DispersionEvidence()
	return v1, s >= 0.75, tm.Refused != ""
}

const reps = 300

func rate(g gen, art artifact, n int, S float64, c2 bool, seed uint64) (float64, float64, float64) {
	r := rand.New(rand.NewPCG(seed, 99))
	var a, b, rf int
	for i := 0; i < reps; i++ {
		t := g(r, n)
		if art != nil {
			t = art(r, t, S)
		}
		x, y, z := detect(t, c2, r)
		if x {
			a++
		}
		if y {
			b++
		}
		if z {
			rf++
		}
	}
	return float64(a) / reps, float64(b) / reps, float64(rf) / reps
}

func TestStressReport(t *testing.T) {
	if os.Getenv("C2PARSER_STRESS_REPORT") == "" {
		t.Skip("set C2PARSER_STRESS_REPORT=1 to print the full stress grid")
	}
	fmt.Println("== NULLS (false-positive rate; v1 Score≥0.55 / v2 dispersion≥0.75 (Bonferroni q1e-3 of the provisional null))")
	for _, nm := range []string{"poisson", "gamma0.5", "gamma4", "browsing", "jamf15m±5", "gpo90+0-30"} {
		for _, n := range []int{30, 200} {
			a, b, rf := rate(nullGen(nm), nil, n, 60, false, 1)
			fmt.Printf("  %-11s n=%-3d FP v1=%.3f v2=%.3f refused=%.2f\n", nm, n, a, b, rf)
		}
	}
	fmt.Println("== BEACONS S=60s (detection rate v1 / v2), clean artifact, by n")
	for _, pol := range []string{"shorten", "lengthen", "symmetric", "anchored"} {
		for _, j := range []float64{0, 0.3, 0.5, 0.7, 0.9} {
			line := fmt.Sprintf("  %-9s j=%2.0f%%", pol, j*100)
			for _, n := range []int{15, 30, 60, 200} {
				a, b, _ := rate(beaconGen(pol, 60, j), nil, n, 60, true, 2)
				line += fmt.Sprintf(" | n=%-3d %.2f/%.2f", n, a, b)
			}
			fmt.Println(line)
		}
	}
	fmt.Println("== ARTIFACTS (n=60, S=60s) detection v1/v2")
	for _, pol := range []string{"shorten", "lengthen", "symmetric"} {
		for _, j := range []float64{0.1, 0.3, 0.7} {
			line := fmt.Sprintf("  %-9s j=%2.0f%%", pol, j*100)
			for _, ar := range artifacts {
				a, b, _ := rate(beaconGen(pol, 60, j), ar.f, 60, 60, true, 3)
				line += fmt.Sprintf(" | %-10s %.2f/%.2f", ar.name, a, b)
			}
			fmt.Println(line)
		}
	}
}
