package stats

import (
	"math"
	"math/rand/v2"
	"testing"
)

// series builds event times from gaps.
func series(gaps []float64) []float64 {
	t := make([]float64, len(gaps)+1)
	for i, g := range gaps {
		t[i+1] = t[i] + g
	}
	return t
}

func gapsOf(n int, f func() float64) []float64 {
	g := make([]float64, n)
	for i := range g {
		g[i] = f()
	}
	return g
}

// Spec Q2.3 gate: the generated Poisson tables reproduce the research's
// simulated quantiles within Monte-Carlo error.
func TestNullTablesMatchResearch(t *testing.T) {
	if nullReps < 100000 {
		t.Fatalf("null tables generated with only %d replicates", nullReps)
	}
	for _, c := range []struct {
		metric string
		n      int
		want   float64
	}{
		{"rh", 9, 0.91}, {"rh", 19, 0.71}, {"rh", 29, 0.61}, {"rh", 49, 0.50}, {"rh", 99, 0.38},
		// R_a stays near naive Rayleigh at n = gaps+1 events = 20/30/50/100.
		{"ra", 19, 0.68}, {"ra", 29, 0.56}, {"ra", 49, 0.44}, {"ra", 99, 0.30},
	} {
		got := NullQuantile(NullPoisson, c.metric, c.n, true, 1e-4)
		if math.Abs(got-c.want) > 0.03 {
			t.Errorf("%s 1−1e-4 quantile at %d gaps = %.3f, research %.2f", c.metric, c.n, got, c.want)
		}
	}
	// The research's 0.110 is the large-n limit of R_h under Poisson; the
	// finite-n mean carries a √(π/4n) noise floor and falls toward it.
	m9, m200 := NullMean(NullPoisson, "rh", 9), NullMean(NullPoisson, "rh", 200)
	if !(m9 > m200 && m200 < 0.135 && m200 > 0.105) {
		t.Errorf("Poisson R_h mean 9→200 gaps: %.3f → %.3f, want decreasing toward 0.11", m9, m200)
	}
}

func TestRefusalLadder(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 1))
	reg := func() float64 { return 60 * (1 - 0.2*r.Float64()) }
	for _, c := range []struct {
		gaps   int
		rung   int
		refuse bool
		rh, ra bool
		approx bool
	}{
		{9, 0, true, false, false, false},
		{15, 10, false, false, false, true},
		{25, 20, false, true, false, true},
		{40, 30, false, true, true, true},
		{60, 50, false, true, true, false},
	} {
		tm := AnalyzeTiming(series(gapsOf(c.gaps, reg)), TimingParams{})
		if (tm.Refused != "") != c.refuse || tm.Rung != c.rung || (tm.Rh != nil) != c.rh || (tm.Ra != nil) != c.ra || (c.rung > 0 && tm.Approx != c.approx) {
			t.Errorf("%d gaps: rung %d refused %q Rh %v Ra %v approx %v", c.gaps, tm.Rung, tm.Refused, tm.Rh != nil, tm.Ra != nil, tm.Approx)
		}
		if c.refuse && tm.CaptureNeededHours <= 0 {
			t.Errorf("%d gaps: refused without capture_needed_hours", c.gaps)
		}
	}
}

// Spread reads differently per jitter polarity (research §3): shortening
// ≈ j, symmetric ≈ 2j/(1+j), lengthening ≈ j/(1+j). With idealised uniform
// jitter both edges are sharp, so polarity reads "uniform".
func TestSpreadByPolarity(t *testing.T) {
	r := rand.New(rand.NewPCG(2, 2))
	const j = 0.3
	cases := []struct {
		name string
		gap  func() float64
		want float64
	}{
		{"shortening", func() float64 { return 60 * (1 - j*r.Float64()) }, j},
		{"symmetric", func() float64 { return 60 * (1 + j*(2*r.Float64()-1)) }, 2 * j / (1 + j)},
		{"lengthening", func() float64 { return 60 + 60*j*r.Float64() }, j / (1 + j)},
	}
	for _, c := range cases {
		tm := AnalyzeTiming(series(gapsOf(400, c.gap)), TimingParams{})
		if tm.Spread == nil || math.Abs(*tm.Spread-c.want) > 0.05 {
			t.Errorf("%s 30%%: spread %v, want ≈%.2f", c.name, tm.Spread, c.want)
		}
		if tm.Polarity != "uniform" {
			t.Errorf("%s: polarity %q, want uniform (both edges sharp)", c.name, tm.Polarity)
		}
	}
}

// One sharp edge + one exponential tail → one-sided polarity labels.
func TestPolarityEdges(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 3))
	sharpLow := func() float64 { return 60 + 60*0.3*r.Float64() + 4*r.ExpFloat64() }  // floor at 60, soft top
	sharpHigh := func() float64 { return 78 - 60*0.3*r.Float64() - 4*r.ExpFloat64() } // ceiling at 78, soft bottom
	if p := AnalyzeTiming(series(gapsOf(400, sharpLow)), TimingParams{}).Polarity; p != "lengthening-like" {
		t.Errorf("sharp lower edge: %q", p)
	}
	if p := AnalyzeTiming(series(gapsOf(400, sharpHigh)), TimingParams{}).Polarity; p != "shortening-like" {
		t.Errorf("sharp upper edge: %q", p)
	}
}

// Anchored grid + random delay: gap_i = P + d_i − d_{i−1} → ρ₁ ≈ −0.5.
func TestAnchoredScheduler(t *testing.T) {
	r := rand.New(rand.NewPCG(4, 4))
	var times []float64
	for i := 0; i < 80; i++ {
		times = append(times, float64(i)*3600+600*r.Float64())
	}
	tm := AnalyzeTiming(times, TimingParams{})
	if !tm.Anchored || tm.Rho1 == nil || *tm.Rho1 > -0.35 {
		t.Fatalf("anchored scheduler not recognised: anchored=%v rho1=%v", tm.Anchored, tm.Rho1)
	}
}

// Dispersion is the detector: periodic-with-jitter fires, Poisson rarely.
func TestDispersionEvidence(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 5))
	for _, c := range []struct {
		name string
		gap  func() float64
	}{
		{"shortening 70%", func() float64 { return 60 * (1 - 0.7*r.Float64()) }},
		{"symmetric 30%", func() float64 { return 60 * (1 + 0.3*(2*r.Float64()-1)) }},
		{"lengthening 50%", func() float64 { return 60 + 30*r.Float64() }},
	} {
		s, _ := AnalyzeTiming(series(gapsOf(40, c.gap)), TimingParams{}).DispersionEvidence()
		if s < 0.75 {
			t.Errorf("%s at 40 gaps: dispersion evidence %.2f, want ≥ 0.75", c.name, s)
		}
	}
	fires := 0
	for i := 0; i < 500; i++ {
		s, _ := AnalyzeTiming(series(gapsOf(40, func() float64 { return 60 * r.ExpFloat64() })), TimingParams{}).DispersionEvidence()
		if s > 0 {
			fires++
		}
	}
	if fires > 5 { // gamma(2) null at 1e-2 is far stricter than Poisson
		t.Errorf("Poisson series gave dispersion evidence in %d/500 runs", fires)
	}
}

func TestKimJoAn(t *testing.T) {
	if v := KimJoAn(0, 20); math.Abs(v+1) > 1e-9 {
		t.Errorf("A_n(CV=0) = %.3f, want −1", v)
	}
	// converges to plain B = (r−1)/(r+1) for large n
	if a, b := KimJoAn(0.5, 1_000_000), (0.5-1)/(0.5+1); math.Abs(a-b) > 0.01 {
		t.Errorf("A_n large n %.3f vs B %.3f", a, b)
	}
}

// Families: correlated UA oddities can't stack into medium on their own;
// without grouping (plain noisy-OR) the same three signals reach medium.
func TestFamiliesCapUA(t *testing.T) {
	sigs := []Signal{
		{Name: "hdr:ua_browser_without_browser_headers", Weight: 0.4, Score: 1},
		{Name: "hdr:ua_stale_browser", Weight: 0.3, Score: 1},
		{Name: "hdr:ua_legacy_msie", Weight: 0.3, Score: 1},
	}
	AssignFamilies(sigs)
	if g := NoisyORFamilies(sigs); g >= 0.4 {
		t.Errorf("UA-only with families = %.2f, want < 0.4", g)
	}
	if p := NoisyOR(sigs); p < 0.4 {
		t.Errorf("mutation check: UA-only without families = %.2f, expected ≥ 0.4", p)
	}
	// singleton families reproduce plain noisy-OR
	other := []Signal{{Name: "a", Weight: 0.5, Score: 1}, {Name: "b", Weight: 0.5, Score: 0.6}}
	if math.Abs(NoisyORFamilies(other)-NoisyOR(other)) > 1e-12 {
		t.Error("singleton families differ from noisy-OR")
	}
	// in-family: max + 0.3 × second
	fam := []Signal{{Name: "timing_dispersion", Weight: 1, Score: 0.8}, {Name: "timing_dispersion_k1", Weight: 1, Score: 0.5}}
	if g, want := NoisyORFamilies(fam), 1-(1-0.8)*(1-0.3*0.5); math.Abs(g-want) > 1e-12 {
		t.Errorf("family combine %.4f, want %.4f", g, want)
	}
}
