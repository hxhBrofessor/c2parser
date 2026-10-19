package eval

import (
	"math"
	"sort"
)

// 95 % intervals used by the report.

const z95 = 1.959963984540054

// wilson is the Wilson score interval for k successes in n trials.
func wilson(k, n int) Prop {
	if n == 0 {
		return Prop{}
	}
	p := float64(k) / float64(n)
	nn := float64(n)
	d := 1 + z95*z95/nn
	c := (p + z95*z95/(2*nn)) / d
	h := z95 * math.Sqrt(p*(1-p)/nn+z95*z95/(4*nn*nn)) / d
	return Prop{K: k, N: n, P: round4(p), Lo: round4(math.Max(0, c-h)), Hi: round4(math.Min(1, c+h))}
}

// poissonCI is Byar's approximation to the exact (Garwood) 95 % interval
// for a Poisson count k; within 1 % of exact for k ≥ 1.
func poissonCI(k int) (lo, hi float64) {
	if k > 0 {
		x := float64(k)
		lo = x * math.Pow(1-1/(9*x)-z95/(3*math.Sqrt(x)), 3)
	}
	y := float64(k + 1)
	hi = y * math.Pow(1-1/(9*y)+z95/(3*math.Sqrt(y)), 3)
	return lo, hi
}

func rate(k int, hours float64) Rate {
	if hours <= 0 {
		return Rate{Count: k}
	}
	lo, hi := poissonCI(k)
	return Rate{Count: k, Rate: round6(float64(k) / hours), Lo: round6(lo / hours), Hi: round6(hi / hours)}
}

// quantileCI is the distribution-free 95 % interval for the p-quantile of
// sorted v: order statistics at ranks n·p ∓ z·√(n·p·(1−p)) (normal
// approximation to the binomial). A side whose rank falls outside the
// sample is nil — the data cannot bound it.
func quantileCI(v []float64, p float64) (lo, hi *float64) {
	n := len(v)
	if n == 0 || !sort.Float64sAreSorted(v) {
		return nil, nil
	}
	m := float64(n) * p
	sd := math.Sqrt(float64(n) * p * (1 - p))
	l := int(math.Floor(m - z95*sd)) // 1-based rank
	u := int(math.Ceil(m+z95*sd)) + 1
	if l >= 1 {
		x := v[l-1]
		lo = &x
	}
	if u <= n {
		x := v[u-1]
		hi = &x
	}
	return lo, hi
}

func round4(x float64) float64 { return math.Round(x*1e4) / 1e4 }
func round6(x float64) float64 { return math.Round(x*1e6) / 1e6 }
