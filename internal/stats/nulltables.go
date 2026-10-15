package stats

import "math"

//go:generate go run ./nullgen -reps 200000 -out nulltables_gen.go

// NullRow is one gap-count row of a generated null table.
type NullRow struct {
	N       int
	Mean    float64
	Defined float64    // share of replicates where the metric was computable
	Q       [6]float64 // lower 1e-2, 1e-3, 1e-4; upper 1−1e-2, 1−1e-3, 1−1e-4
}

// Null families available in nulltables_gen.go.
const (
	NullPoisson = "poisson"
	NullGamma05 = "gamma0.5"
	NullGamma2  = "gamma2"
	NullGamma4  = "gamma4"
)

func alphaIndex(alpha float64) int {
	switch {
	case alpha >= 1e-2:
		return 0
	case alpha >= 1e-3:
		return 1
	}
	return 2
}

// NullQuantile returns the null quantile of metric at gap count n
// (interpolated in log n, clamped to the grid), lower or upper tail, at
// alpha ∈ {1e-2, 1e-3, 1e-4}. NaN when the table has no value.
func NullQuantile(family, metric string, n int, upper bool, alpha float64) float64 {
	rows := nullTables[family][metric]
	if len(rows) == 0 || n <= 0 {
		return math.NaN()
	}
	k := alphaIndex(alpha)
	if upper {
		k += 3
	}
	if n <= rows[0].N {
		return rows[0].Q[k]
	}
	last := rows[len(rows)-1]
	if n >= last.N {
		return last.Q[k]
	}
	for i := 1; i < len(rows); i++ {
		if n <= rows[i].N {
			a, b := rows[i-1], rows[i]
			t := (math.Log(float64(n)) - math.Log(float64(a.N))) / (math.Log(float64(b.N)) - math.Log(float64(a.N)))
			return a.Q[k]*(1-t) + b.Q[k]*t
		}
	}
	return math.NaN()
}

// NullMean returns the tabulated null mean at the nearest grid n.
func NullMean(family, metric string, n int) float64 {
	rows := nullTables[family][metric]
	best := math.NaN()
	bd := math.MaxInt
	for _, r := range rows {
		d := r.N - n
		if d < 0 {
			d = -d
		}
		if d < bd {
			bd, best = d, r.Mean
		}
	}
	return best
}
