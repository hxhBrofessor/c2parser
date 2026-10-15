package eval

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Calibration harness (v10a 1.5). Built now, run in v10c on real data:
//
//   - L2-penalised logistic regression over per-family scores;
//   - nested leave-one-framework-out: the outer loop holds out one
//     framework (and a matching share of benign rows) for testing; the
//     inner loop picks the penalty λ by leave-one-framework-out on what
//     remains and collects out-of-fold scores for Platt calibration;
//   - Platt scaling of the fitted logit.
//
// It writes a proposed-weights file and a held-out comparison against the
// product's own score. It never edits product weights: a human reads the
// comparison and copies weights across after review.

// CalRow is one training example.
type CalRow struct {
	Group   string             `json:"group"`   // framework for positives; "" for benign
	Label   int                `json:"label"`   // 1 = C2, 0 = benign
	X       map[string]float64 `json:"x"`       // family → score in [0, 1]
	Product float64            `json:"product"` // the product's score for the same row (comparison)
}

// CalOptions configure Fit.
type CalOptions struct {
	Lambdas  []float64 // penalty grid (default 0, 1e-4, 1e-3, 1e-2, 0.1, 1, 10)
	Features []string  // default: every family seen
	MaxIter  int       // Newton iterations (default 50)
}

// Fold is one outer held-out fold.
type Fold struct {
	Framework      string  `json:"framework"`
	Lambda         float64 `json:"lambda"`
	N              int     `json:"n"`
	Positives      int     `json:"positives"`
	LogLoss        float64 `json:"log_loss"`
	Brier          float64 `json:"brier"`
	ProductLogLoss float64 `json:"product_log_loss"`
	ProductBrier   float64 `json:"product_brier"`
}

// Calibration is the harness output.
type Calibration struct {
	Status    string             `json:"status"` // always "proposed — not applied"
	Features  []string           `json:"features"`
	Lambda    float64            `json:"lambda"`
	Intercept float64            `json:"intercept"`
	Weights   map[string]float64 `json:"weights"`
	PlattA    float64            `json:"platt_a"` // p = σ(A·logit + B)
	PlattB    float64            `json:"platt_b"`
	Rows      int                `json:"rows"`
	Positives int                `json:"positives"`
	HeldOut   []Fold             `json:"held_out"`
	Notes     []string           `json:"notes,omitempty"`
}

var defaultLambdas = []float64{0, 1e-4, 1e-3, 1e-2, 0.1, 1, 10}

func sigmoid(z float64) float64 {
	if z >= 0 {
		return 1 / (1 + math.Exp(-z))
	}
	e := math.Exp(z)
	return e / (1 + e)
}

func clampP(p float64) float64 { return math.Min(1-1e-12, math.Max(1e-12, p)) }

// logistic fits β (intercept first) by Newton's method on the penalised
// log-likelihood; the intercept is not penalised. X rows are dense.
func logistic(X [][]float64, y []float64, lambda float64, maxIter int) ([]float64, error) {
	if len(X) == 0 {
		return nil, errors.New("no rows")
	}
	d := len(X[0]) + 1
	beta := make([]float64, d)
	for it := 0; it < maxIter; it++ {
		g := make([]float64, d)
		H := make([][]float64, d)
		for i := range H {
			H[i] = make([]float64, d)
		}
		for r, x := range X {
			z := beta[0]
			for j, v := range x {
				z += beta[j+1] * v
			}
			p := sigmoid(z)
			w := math.Max(p*(1-p), 1e-10)
			e := y[r] - p
			g[0] += e
			H[0][0] += w
			for j, v := range x {
				g[j+1] += e * v
				H[0][j+1] += w * v
				for k := j; k < len(x); k++ {
					H[j+1][k+1] += w * v * x[k]
				}
			}
		}
		for j := 1; j < d; j++ {
			g[j] -= lambda * beta[j]
			H[j][j] += lambda
			for k := 0; k < j; k++ {
				H[j][k] = H[k][j]
			}
		}
		step, err := solve(H, g)
		if err != nil {
			return nil, err
		}
		mx := 0.0
		for j := range beta {
			beta[j] += step[j]
			mx = math.Max(mx, math.Abs(step[j]))
		}
		if mx < 1e-9 {
			break
		}
	}
	return beta, nil
}

// solve is Gaussian elimination with partial pivoting (A is copied).
func solve(A [][]float64, b []float64) ([]float64, error) {
	n := len(b)
	M := make([][]float64, n)
	for i := range M {
		M[i] = append(append([]float64(nil), A[i]...), b[i])
	}
	for c := 0; c < n; c++ {
		p := c
		for r := c + 1; r < n; r++ {
			if math.Abs(M[r][c]) > math.Abs(M[p][c]) {
				p = r
			}
		}
		if math.Abs(M[p][c]) < 1e-12 {
			return nil, errors.New("singular system (a feature is constant or collinear; add λ > 0)")
		}
		M[c], M[p] = M[p], M[c]
		for r := c + 1; r < n; r++ {
			f := M[r][c] / M[c][c]
			for k := c; k <= n; k++ {
				M[r][k] -= f * M[c][k]
			}
		}
	}
	x := make([]float64, n)
	for r := n - 1; r >= 0; r-- {
		s := M[r][n]
		for k := r + 1; k < n; k++ {
			s -= M[r][k] * x[k]
		}
		x[r] = s / M[r][r]
	}
	return x, nil
}

func linear(beta, x []float64) float64 {
	z := beta[0]
	for j, v := range x {
		z += beta[j+1] * v
	}
	return z
}

// platt fits p = σ(A·s + B) with Platt's smoothed targets.
func platt(s, y []float64) (a, b float64) {
	np, nn := 0.0, 0.0
	for _, v := range y {
		if v > 0.5 {
			np++
		} else {
			nn++
		}
	}
	tp, tn := (np+1)/(np+2), 1/(nn+2)
	t := make([]float64, len(y))
	X := make([][]float64, len(s))
	for i := range s {
		X[i] = []float64{s[i]}
		t[i] = tn
		if y[i] > 0.5 {
			t[i] = tp
		}
	}
	beta, err := logistic(X, t, 0, 100)
	if err != nil {
		return 1, 0
	}
	return beta[1], beta[0]
}

type calData struct {
	X      [][]float64
	y      []float64
	group  []string
	fold   []int // benign rows: outer fold index; positives: framework index
	prod   []float64
	groups []string
}

func (c *calData) subset(keep func(i int) bool) *calData {
	o := &calData{groups: c.groups}
	for i := range c.X {
		if keep(i) {
			o.X, o.y, o.group, o.fold, o.prod = append(o.X, c.X[i]), append(o.y, c.y[i]), append(o.group, c.group[i]), append(o.fold, c.fold[i]), append(o.prod, c.prod[i])
		}
	}
	return o
}

// lofo runs leave-one-framework-out over d's frameworks at λ and returns
// mean held-out log-loss plus the out-of-fold logits.
func lofo(d *calData, lambda float64, maxIter int) (float64, []float64, error) {
	fws := map[int]bool{}
	for i, y := range d.y {
		if y > 0.5 {
			fws[d.fold[i]] = true
		}
	}
	if len(fws) < 2 {
		return 0, nil, errors.New("leave-one-framework-out needs ≥ 2 frameworks")
	}
	oof := make([]float64, len(d.y))
	loss, n := 0.0, 0
	for f := range fws {
		test := func(i int) bool { return d.fold[i] == f }
		tr := d.subset(func(i int) bool { return !test(i) })
		beta, err := logistic(tr.X, tr.y, lambda, maxIter)
		if err != nil {
			return 0, nil, err
		}
		for i := range d.y {
			if test(i) {
				z := linear(beta, d.X[i])
				oof[i] = z
				p := clampP(sigmoid(z))
				loss -= d.y[i]*math.Log(p) + (1-d.y[i])*math.Log(1-p)
				n++
			}
		}
	}
	return loss / float64(max(n, 1)), oof, nil
}

func pickLambda(d *calData, lambdas []float64, maxIter int) (best float64, oof []float64, err error) {
	bl := math.Inf(1)
	for _, l := range lambdas {
		loss, o, e := lofo(d, l, maxIter)
		if e != nil {
			continue // e.g. singular at λ = 0
		}
		if loss < bl-1e-12 {
			bl, best, oof = loss, l, o
		}
	}
	if oof == nil {
		return 0, nil, errors.New("no penalty in the grid gave a fit")
	}
	return best, oof, nil
}

// Fit runs the nested leave-one-framework-out calibration.
func Fit(rows []CalRow, opt CalOptions) (*Calibration, error) {
	if len(opt.Lambdas) == 0 {
		opt.Lambdas = defaultLambdas
	}
	if opt.MaxIter == 0 {
		opt.MaxIter = 50
	}
	feats := opt.Features
	if len(feats) == 0 {
		seen := map[string]bool{}
		for _, r := range rows {
			for k := range r.X {
				seen[k] = true
			}
		}
		for k := range seen {
			feats = append(feats, k)
		}
		sort.Strings(feats)
	}
	d := &calData{}
	fwIdx := map[string]int{}
	for _, r := range rows {
		if r.Label == 1 {
			if _, ok := fwIdx[r.Group]; !ok {
				fwIdx[r.Group] = len(d.groups)
				d.groups = append(d.groups, r.Group)
			}
		}
	}
	k := len(d.groups)
	if k < 3 {
		return nil, fmt.Errorf("nested leave-one-framework-out needs ≥ 3 frameworks with positives, have %d", k)
	}
	nb := 0
	for _, r := range rows {
		x := make([]float64, len(feats))
		for j, f := range feats {
			x[j] = r.X[f]
		}
		fold := fwIdx[r.Group]
		if r.Label != 1 {
			fold = nb % k // benign rows spread evenly over the folds
			nb++
		}
		d.X, d.y, d.group, d.fold, d.prod = append(d.X, x), append(d.y, float64(r.Label)), append(d.group, r.Group), append(d.fold, fold), append(d.prod, r.Product)
	}
	if nb == 0 {
		return nil, errors.New("no benign rows")
	}
	cal := &Calibration{Status: "proposed — not applied; a human copies weights after review", Features: feats, Rows: len(rows), Positives: len(rows) - nb}
	// outer loop
	for f, name := range d.groups {
		test := func(i int) bool { return d.fold[i] == f }
		tr := d.subset(func(i int) bool { return !test(i) })
		lambda, oof, err := pickLambda(tr, opt.Lambdas, opt.MaxIter)
		if err != nil {
			return nil, fmt.Errorf("outer fold %s: %w", name, err)
		}
		beta, err := logistic(tr.X, tr.y, lambda, opt.MaxIter)
		if err != nil {
			return nil, err
		}
		a, b := platt(oof, tr.y)
		fd := Fold{Framework: name, Lambda: lambda}
		for i := range d.y {
			if !test(i) {
				continue
			}
			p := clampP(sigmoid(a*linear(beta, d.X[i]) + b))
			q := clampP(d.prod[i])
			y := d.y[i]
			fd.N++
			if y > 0.5 {
				fd.Positives++
			}
			fd.LogLoss -= y*math.Log(p) + (1-y)*math.Log(1-p)
			fd.ProductLogLoss -= y*math.Log(q) + (1-y)*math.Log(1-q)
			fd.Brier += (p - y) * (p - y)
			fd.ProductBrier += (q - y) * (q - y)
		}
		if fd.N > 0 {
			n := float64(fd.N)
			fd.LogLoss, fd.ProductLogLoss, fd.Brier, fd.ProductBrier = round4(fd.LogLoss/n), round4(fd.ProductLogLoss/n), round4(fd.Brier/n), round4(fd.ProductBrier/n)
		}
		cal.HeldOut = append(cal.HeldOut, fd)
	}
	// final fit on everything
	lambda, oof, err := pickLambda(d, opt.Lambdas, opt.MaxIter)
	if err != nil {
		return nil, err
	}
	beta, err := logistic(d.X, d.y, lambda, opt.MaxIter)
	if err != nil {
		return nil, err
	}
	cal.Lambda, cal.Intercept = lambda, beta[0]
	cal.Weights = map[string]float64{}
	for j, f := range feats {
		cal.Weights[f] = beta[j+1]
	}
	cal.PlattA, cal.PlattB = platt(oof, d.y)
	cal.Notes = append(cal.Notes, "Weights are logistic coefficients on family scores, not noisy-OR weights; mapping them into the product is a reviewed, manual step.")
	return cal, nil
}

// CalibrateReport fits the report's calibration rows, refusing below
// MinBenignSeries benign series (v10a.1 D1): small samples can be looked
// at, but cannot set weights.
func CalibrateReport(r *Report, opt CalOptions) (*Calibration, error) {
	if r.BenignSeries < MinBenignSeries {
		return nil, fmt.Errorf("%d benign series, fewer than the %d calibration needs", r.BenignSeries, MinBenignSeries)
	}
	cal, err := Fit(r.CalibrationRows(), opt)
	if err == nil && r.Synthetic {
		cal.Notes = append([]string{Banner}, cal.Notes...)
	}
	return cal, err
}

// Write saves proposed-weights.json and calibration.md into dir.
func (c *Calibration) Write(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "proposed-weights.json"), b, 0o644); err != nil {
		return err
	}
	var s strings.Builder
	fmt.Fprintf(&s, "# Calibration (proposed — not applied)\n\n%d rows (%d C2). λ = %g. Platt: p = σ(%.4f·z %+.4f).\n\n", c.Rows, c.Positives, c.Lambda, c.PlattA, c.PlattB)
	fmt.Fprintf(&s, "| Family | Weight |\n|---|---|\n| (intercept) | %.4f |\n", c.Intercept)
	for _, f := range c.Features {
		fmt.Fprintf(&s, "| %s | %.4f |\n", f, c.Weights[f])
	}
	s.WriteString("\n## Held-out (nested leave-one-framework-out) vs the product score\n\n| Held-out framework | λ | n | C2 | Log-loss | Product log-loss | Brier | Product Brier |\n|---|---|---|---|---|---|---|---|\n")
	for _, f := range c.HeldOut {
		fmt.Fprintf(&s, "| %s | %g | %d | %d | %.4f | %.4f | %.4f | %.4f |\n", f.Framework, f.Lambda, f.N, f.Positives, f.LogLoss, f.ProductLogLoss, f.Brier, f.ProductBrier)
	}
	for _, n := range c.Notes {
		fmt.Fprintf(&s, "\n%s\n", n)
	}
	return os.WriteFile(filepath.Join(dir, "calibration.md"), []byte(s.String()), 0o644)
}
