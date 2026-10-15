package stats

import (
	"math"
	"sort"
)

// Beacon summarises how machine-like a series of events is.
//
// Inspired by RITA's beacon analysis, but tightened so that a Poisson
// (human/random) arrival process scores low: the dispersion term uses
// 2·MAD/median, which is ≈1.4 for exponential gaps (→ score 0) and ≈0.2 for
// a 10%-jittered sleep timer (→ 0.8).
type Beacon struct {
	Events    int     `json:"events"`
	SpanSec   float64 `json:"span_sec"`
	MedianSec float64 `json:"median_interval_sec"`
	MADSec    float64 `json:"mad_interval_sec"`
	P10Sec    float64 `json:"p10_interval_sec"`
	P90Sec    float64 `json:"p90_interval_sec"`
	JitterPct float64 `json:"jitter_pct"` // MAD/median*100
	MeanSec   float64 `json:"mean_interval_sec"`
	SDSec     float64 `json:"sd_interval_sec"`
	CV        float64 `json:"cv"` // SD/mean: ~0 for a timer, ~1 for Poisson
	TSWindow  float64 `json:"ts_window_share"`
	// z-score of the on-period share vs. a Poisson process (binomial test)
	Significance float64 `json:"significance_z"`
	TSSkew       float64 `json:"ts_skew"`
	TSDisp       float64 `json:"ts_dispersion"`
	TSCoverage   float64 `json:"ts_coverage"`
	TSScore      float64 `json:"ts_score"`
	ModeSize     float64 `json:"mode_size"`
	DSSkew       float64 `json:"ds_skew"`
	DSDisp       float64 `json:"ds_dispersion"`
	DSMode       float64 `json:"ds_mode_share"`
	DSScore      float64 `json:"ds_score"`
	Score        float64 `json:"score"`
}

// BeaconParams tune ScoreBeacon.
type BeaconParams struct {
	MinEvents  int // below this, no score
	FullEvents int // at/above this, full confidence
}

// DefaultBeaconParams are sane for minutes-to-hours captures.
var DefaultBeaconParams = BeaconParams{MinEvents: 8, FullEvents: 40}

// ScoreBeacon scores event times (seconds, ascending) and the payload size
// of each event. ok=false if there are too few events.
func ScoreBeacon(times, sizes []float64, p BeaconParams) (b Beacon, ok bool) {
	b.Events = len(times)
	if p.MinEvents < 3 {
		p.MinEvents = 3
	}
	if p.FullEvents <= p.MinEvents {
		p.FullEvents = p.MinEvents + 1
	}
	if len(times) < p.MinEvents {
		return b, false
	}
	times, sizes = sortPairs(times, sizes)
	gaps := make([]float64, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		gaps = append(gaps, times[i]-times[i-1])
	}
	b.SpanSec = times[len(times)-1] - times[0]
	sg := Sorted(gaps)
	b.MedianSec = Quantile(sg, .5)
	b.P10Sec, b.P90Sec = Quantile(sg, .1), Quantile(sg, .9)
	if b.MedianSec <= 1e-6 {
		return b, false // a single burst, not a beacon
	}
	b.MADSec = MAD(gaps, b.MedianSec)
	b.JitterPct = 100 * b.MADSec / b.MedianSec

	for _, g := range gaps {
		b.MeanSec += g
	}
	b.MeanSec /= float64(len(gaps))
	for _, g := range gaps {
		b.SDSec += (g - b.MeanSec) * (g - b.MeanSec)
	}
	b.SDSec = math.Sqrt(b.SDSec / float64(len(gaps)))
	if b.MeanSec > 0 {
		b.CV = b.SDSec / b.MeanSec
	}

	b.TSSkew = 1 - math.Abs(Bowley(sg))
	b.TSDisp = clamp01(1 - 2*b.MADSec/b.MedianSec)
	b.TSCoverage = clamp01(float64(len(gaps)) * b.MedianSec / b.SpanSec)
	b.TSWindow = windowShare(gaps, b.MedianSec)
	b.TSScore = 0.2*b.TSSkew + 0.35*b.TSDisp + 0.2*b.TSCoverage + 0.25*b.TSWindow

	if len(sizes) == len(times) {
		ss := Sorted(sizes)
		med := Quantile(ss, .5)
		b.DSSkew = 1 - math.Abs(Bowley(ss))
		if med > 0 {
			b.DSDisp = clamp01(1 - 2*MAD(sizes, med)/med)
		} else if Quantile(ss, 1) == 0 {
			b.DSDisp = 1
		}
		b.ModeSize, b.DSMode = ModeFraction(sizes, 1)
		b.DSScore = (b.DSSkew + b.DSDisp + b.DSMode) / 3
	}

	// Confidence from a one-sided binomial test of the on-period share
	// against the Poisson null (P≈0.27 that an exponential gap lands in the
	// window). This replaces a linear ramp in n: eight perfectly regular
	// gaps already give z≈4.7, while 200 random gaps give z≈0.
	b.Significance = beaconZ(b.TSWindow, len(gaps))
	conf := Smoothstep(2, 6, b.Significance)
	b.Score = (0.65*b.TSScore + 0.35*b.DSScore) * (0.6 + 0.4*conf)
	return b, true
}

// sortPairs returns time-ordered copies (events from concurrent connections
// are appended out of order).
func sortPairs(t, s []float64) ([]float64, []float64) {
	idx := make([]int, len(t))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return t[idx[a]] < t[idx[b]] })
	ot := make([]float64, len(t))
	var os []float64
	if len(s) == len(t) {
		os = make([]float64, len(s))
	}
	for i, j := range idx {
		ot[i] = t[j]
		if os != nil {
			os[i] = s[j]
		}
	}
	return ot, os
}

// windowShare is the share of gaps that sit on the beacon period: within
// ±30% of the median (covers sleep timers with up to ~50% jitter, e.g. a
// Cobalt Strike 60 s ±15% profile lands in 51–69 s), with gaps at 2× and 3×
// the period (a missed or merged check-in) counted at half credit inside a
// ±10% window. Poisson traffic scores ≈0.27; a jittered timer ≈1.
func windowShare(gaps []float64, period float64) float64 {
	if len(gaps) == 0 || period <= 0 {
		return 0
	}
	in := 0.0
	for _, g := range gaps {
		r := g / period
		switch {
		case r >= 0.7 && r <= 1.3:
			in++
		case math.Abs(r-2) <= 0.2 || math.Abs(r-3) <= 0.3:
			in += 0.5
		}
	}
	return in / float64(len(gaps))
}

// poissonWindowP is the probability that an exponential inter-arrival lands
// in windowShare's scoring region (±30% of the median, plus half-credit 2×/3×
// windows), computed for median = ln2·μ: P[0.7m,1.3m] + ½(P[1.8m,2.2m] + P[2.7m,3.3m]).
var poissonWindowP = func() float64 {
	m := math.Ln2
	p := func(a, b float64) float64 { return math.Exp(-a*m) - math.Exp(-b*m) }
	return p(0.7, 1.3) + 0.5*(p(1.8, 2.2)+p(2.7, 3.3))
}()

func beaconZ(share float64, n int) float64 {
	if n == 0 {
		return 0
	}
	p := poissonWindowP
	return (share - p) * math.Sqrt(float64(n)) / math.Sqrt(p*(1-p))
}
