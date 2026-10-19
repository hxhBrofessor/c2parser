package eval

import (
	"math"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// synthCal draws rows from a known logistic model over four family
// scores: 5 frameworks of positives and benign rows, labels Bernoulli.
func synthCal(n int, seed uint64) ([]CalRow, map[string]float64, float64) {
	w := map[string]float64{"timing": 1.5, "transport_anomaly": -0.8, "content": 2.2, "recon": 0.5}
	b := -1.0
	r := mrand.New(mrand.NewPCG(seed, seed^7))
	fams := []string{"content", "recon", "timing", "transport_anomaly"}
	var rows []CalRow
	for i := 0; i < n; i++ {
		x := map[string]float64{}
		z := b
		for _, f := range fams {
			x[f] = r.Float64()
			z += w[f] * x[f]
		}
		y := 0
		if r.Float64() < sigmoid(z) {
			y = 1
		}
		g := ""
		if y == 1 {
			g = []string{"fw-a", "fw-b", "fw-c", "fw-d", "fw-e"}[r.IntN(5)]
		}
		rows = append(rows, CalRow{Group: g, Label: y, X: x, Product: 0.5})
	}
	return rows, w, b
}

// v10a 1.5 gate: on synthetic data with known generating weights, the
// nested leave-one-framework-out fit recovers every weight within 0.05.
// Mutation: forcing a heavy penalty (λ = 1000) breaks the recovery.
func TestCalibrationRecoversWeights(t *testing.T) {
	if testing.Short() {
		t.Skip("calibration")
	}
	rows, w, b := synthCal(300000, 11)
	cal, err := Fit(rows, CalOptions{Lambdas: []float64{0, 1e-3, 10}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("λ=%g intercept %.3f weights %v platt (%.3f, %.3f)", cal.Lambda, cal.Intercept, cal.Weights, cal.PlattA, cal.PlattB)
	for f, want := range w {
		if math.Abs(cal.Weights[f]-want) > 0.05 {
			t.Errorf("%s: %.3f, want %.3f ± 0.05", f, cal.Weights[f], want)
		}
	}
	if math.Abs(cal.Intercept-b) > 0.05 {
		t.Errorf("intercept %.3f, want %.3f", cal.Intercept, b)
	}
	if len(cal.HeldOut) != 5 {
		t.Fatalf("held-out folds: %+v", cal.HeldOut)
	}
	for _, f := range cal.HeldOut {
		if f.N == 0 || f.LogLoss >= f.ProductLogLoss {
			t.Errorf("fold %s: fitted log-loss %.4f not better than a constant 0.5 product score (%.4f)", f.Framework, f.LogLoss, f.ProductLogLoss)
		}
	}
	if math.Abs(cal.PlattA-1) > 0.1 || math.Abs(cal.PlattB) > 0.1 {
		t.Errorf("Platt on a well-specified model should be near identity: (%.3f, %.3f)", cal.PlattA, cal.PlattB)
	}
	dir := t.TempDir()
	if err := cal.Write(dir); err != nil {
		t.Fatal(err)
	}
	md, _ := os.ReadFile(filepath.Join(dir, "calibration.md"))
	js, _ := os.ReadFile(filepath.Join(dir, "proposed-weights.json"))
	if !strings.Contains(string(md), "proposed — not applied") || !strings.Contains(string(js), `"status": "proposed`) {
		t.Error("output not marked as proposed")
	}

	heavy, err := Fit(rows[:60000], CalOptions{Lambdas: []float64{1000}})
	if err != nil {
		t.Fatal(err)
	}
	off := 0
	for f, want := range w {
		if math.Abs(heavy.Weights[f]-want) > 0.05 {
			off++
		}
	}
	if off == 0 {
		t.Error("mutation: λ = 1000 still recovers the weights — the check cannot see shrinkage")
	}
}

func TestCalibrationNeedsFrameworks(t *testing.T) {
	rows, _, _ := synthCal(2000, 3)
	for i := range rows {
		if rows[i].Label == 1 {
			rows[i].Group = []string{"a", "b"}[i%2]
		}
	}
	if _, err := Fit(rows, CalOptions{}); err == nil {
		t.Error("nested LOFO with 2 frameworks accepted")
	}
}

// v10a.1 D1: calibration and the default-flip data gate need ≥ 1000
// benign series of real data.
func TestCalibrationAndFlipFloor(t *testing.T) {
	rows, _, _ := synthCal(4000, 5)
	mk := func(nBenign int, synthetic bool) *Report {
		r := &Report{Synthetic: synthetic, calRows: rows}
		for i := 0; i < nBenign; i++ {
			r.Series = append(r.Series, Series{Label: "benign", V2: float64(i%100) / 100})
		}
		r.summarise()
		return r
	}
	small := mk(999, false)
	if _, err := CalibrateReport(small, CalOptions{Lambdas: []float64{1e-3}}); err == nil {
		t.Error("calibration ran on 999 benign series")
	}
	if small.FlipGate.Eligible || len(small.Thresholds) == 0 {
		t.Errorf("999 real benign series: flip %+v, thresholds %v (operating points stay, the flip does not)", small.FlipGate, small.Thresholds)
	}
	big := mk(1000, false)
	if _, err := CalibrateReport(big, CalOptions{Lambdas: []float64{1e-3}}); err != nil || !big.FlipGate.Eligible {
		t.Errorf("1000 real benign series: calibrate %v, flip %+v", err, big.FlipGate)
	}
	if s := mk(5000, true); s.FlipGate.Eligible {
		t.Error("synthetic data passed the flip gate")
	}
}
