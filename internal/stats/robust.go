package stats

import (
	"math"
	"sort"
)

// Sorted returns a sorted copy.
func Sorted(xs []float64) []float64 {
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	return s
}

// Quantile uses linear interpolation on an already-sorted slice.
func Quantile(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	pos := q * float64(len(sorted)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	t := pos - float64(lo)
	return sorted[lo]*(1-t) + sorted[hi]*t
}

// MAD is the median absolute deviation around med.
func MAD(xs []float64, med float64) float64 {
	d := make([]float64, len(xs))
	for i, x := range xs {
		d[i] = math.Abs(x - med)
	}
	sort.Float64s(d)
	return Quantile(d, 0.5)
}

// Bowley returns the quartile skewness (Q1+Q3-2·Q2)/(Q3-Q1) in [-1,1]; 0
// when the IQR is zero (perfectly regular data).
func Bowley(sorted []float64) float64 {
	q1, q2, q3 := Quantile(sorted, .25), Quantile(sorted, .5), Quantile(sorted, .75)
	if q3-q1 < 1e-12 {
		return 0
	}
	return (q1 + q3 - 2*q2) / (q3 - q1)
}

// ModeFraction buckets values to the nearest `tol` and returns the most
// common bucket and the share of samples that fall in it.
func ModeFraction(xs []float64, tol float64) (mode, frac float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	if tol <= 0 {
		tol = 1
	}
	counts := map[int64]int{}
	best, bestN := int64(0), 0
	for _, x := range xs {
		b := int64(math.Round(x / tol))
		counts[b]++
		if counts[b] > bestN || counts[b] == bestN && b < best {
			best, bestN = b, counts[b]
		}
	}
	return float64(best) * tol, float64(bestN) / float64(len(xs))
}

// Smoothstep maps x from [e0,e1] onto [0,1] with an S-curve. Used to turn a
// raw score into evidence: below e0 contributes nothing, above e1 is full.
func Smoothstep(e0, e1, x float64) float64 {
	t := clamp01((x - e0) / (e1 - e0))
	return t * t * (3 - 2*t)
}

// Saturate returns x/(x+half): 0 at 0, 0.5 at `half`, approaching 1.
func Saturate(x, half float64) float64 {
	if x <= 0 || half <= 0 {
		return 0
	}
	return x / (x + half)
}
