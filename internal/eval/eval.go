// Package eval is c2parser's evaluation harness (v8 spec Q0.3; v10a
// Phase 1 data readiness).
//
// It runs the engine with -timing v2 over a manifest of captures (see
// manifest.go), labels every timing series and finding, and reports:
//
//   - per series: event model, refusal, v1 and v2 scores, timing metrics,
//     and two baselines (an approximate RITA-style timestamp score and
//     "n ≥ k events to one destination");
//   - per metric: benign quantiles (1 − 10⁻², 10⁻³, 10⁻⁴) with
//     distribution-free confidence intervals;
//   - Neyman–Pearson operating points: each score's threshold is its benign
//     1 − 10⁻⁴ quantile — positives never set a threshold;
//   - per (framework, transport, sleep, jitter) cell and per jitter cell:
//     TPR at that operating point for v1, v2 and the baselines, with
//     Wilson intervals — no pooled ROC;
//   - worst held-out framework (leave-one-framework-out reduces to the
//     minimum per-framework TPR, because thresholds come from benign data
//     only);
//   - false positives per benign host-hour, per scorer and per severity,
//     with Poisson intervals; the top 20 benign findings;
//   - destination prevalence across the benign set (reported only).
//
// A report built only from synthetic data carries the v9 banner and, with
// fewer than MinBenignSeries benign series, refuses to emit operating
// points.
//
// Datasets stay outside the repo; manifests point at them by path.
package eval

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/goccy/go-yaml"

	"c2parser/internal/stats"
)

// Series is one evaluated row.
type Series struct {
	Capture    string   `json:"capture"`
	Framework  string   `json:"framework,omitempty"`
	Cell       string   `json:"cell,omitempty"`
	Label      string   `json:"label"` // c2 | benign | background
	Site       string   `json:"site"`
	Key        string   `json:"key"`
	Client     string   `json:"client"`
	EventModel string   `json:"event_model"`
	Refused    string   `json:"refused,omitempty"`
	Events     int      `json:"events"`
	V1         float64  `json:"v1"`
	V2         float64  `json:"v2"`
	RITA       float64  `json:"rita_like"`
	CV         *float64 `json:"cv,omitempty"`
	An         *float64 `json:"an,omitempty"`
	Rh         *float64 `json:"rh,omitempty"`
	Spread     *float64 `json:"spread,omitempty"`
	Polarity   string   `json:"polarity,omitempty"`
	PeriodSec  float64  `json:"period_sec"`
	Jitter     string   `json:"jitter_cell,omitempty"` // positives: the capture's jitter cell ("30%", "unknown")
}

// Banner is the v9 synthetic-data banner, repeated on synthetic-only reports.
const Banner = "Regression and robustness evidence only — synthetic data cannot set thresholds or measure real-world accuracy."

// MinBenignSeries is the refusal floor for synthetic-only reports.
const MinBenignSeries = 1000

// Report is the harness output (report_version 2).
type Report struct {
	ReportVersion   int                           `json:"report_version"`
	Manifest        string                        `json:"manifest,omitempty"`
	Synthetic       bool                          `json:"synthetic_only"`
	Banner          string                        `json:"banner,omitempty"`
	Refusal         string                        `json:"refusal,omitempty"`
	Units           []UnitInfo                    `json:"units"`
	Series          []Series                      `json:"series"`
	BenignSeries    int                           `json:"benign_series"`
	C2Series        int                           `json:"c2_series"`
	BenignQuantiles map[string]Quantiles          `json:"benign_quantiles"`
	Thresholds      map[string]float64            `json:"thresholds"` // NP operating points
	Cells           map[string]map[string]float64 `json:"cell_tpr"`   // cell → scorer → TPR
	CellCI          map[string]map[string]Prop    `json:"cell_tpr_ci,omitempty"`
	JitterTPR       map[string]map[string]Prop    `json:"jitter_tpr,omitempty"` // jitter cell → scorer → TPR
	WorstHeldOut    map[string]string             `json:"worst_held_out_framework"`
	BenignHostHours float64                       `json:"benign_host_hours"`
	FPPerHostHour   map[string]float64            `json:"fp_per_benign_host_hour"`
	FPPerHostHourCI map[string]Rate               `json:"fp_per_benign_host_hour_ci,omitempty"`
	FPBySeverity    map[string]Rate               `json:"benign_findings_per_host_hour"` // severity → rate (findings at that severity)
	TopBenign       []BenignFinding               `json:"top_benign_findings,omitempty"`
	Prevalence      []PrevalenceRow               `json:"prevalence,omitempty"`
	Comparison      []ScorerRow                   `json:"scorer_comparison,omitempty"`
	JitterCurve     []JitterRow                   `json:"detection_vs_jitter,omitempty"`
	FlipGate        FlipGate                      `json:"default_flip_gate"`
	Notes           []string                      `json:"notes,omitempty"`

	benignFindings []BenignFinding
	calRows        []CalRow
	prevalence     map[[2]string]map[string]bool
}

// FlipGate is the data floor for flipping the default engine to
// -timing v2 (v10a.1 D1): real (not synthetic-only) data with at least
// MinBenignSeries benign series. Necessary, not sufficient: the flip
// decision also reads TPR and FP rates.
type FlipGate struct {
	BenignSeries int    `json:"benign_series"`
	Required     int    `json:"required"`
	Eligible     bool   `json:"eligible"`
	Reason       string `json:"reason"`
}

// UnitInfo describes one engine run.
type UnitInfo struct {
	Name              string     `json:"name"`
	Role              string     `json:"role"`
	Files             int        `json:"files"`
	DurationSec       float64    `json:"duration_sec"`
	BenignHostHours   float64    `json:"benign_host_hours"`
	ExpectedHostHours float64    `json:"expected_host_hours,omitempty"`
	Series            int        `json:"series"`
	Findings          int        `json:"findings"`
	Join              *JoinStats `json:"zeek_join,omitempty"`
	LabelSource       string     `json:"label_source"`
	Positives         int        `json:"positive_endpoints,omitempty"`
}

// Quantiles are benign quantiles on the suspicious tail of a metric: upper
// (0.99 / 0.999 / 0.9999) for scores and R_h, lower (0.01 / 0.001 / 0.0001)
// for CV, A_n and spread, where low values are the regular, suspicious end.
// Lo/Hi are 95 % distribution-free (order-statistic) bounds; nil means the
// sample is too small to bound that side.
type Quantiles struct {
	Tail string      `json:"tail"`
	Q    [3]float64  `json:"q"`
	N    int         `json:"n,omitempty"`
	Lo   [3]*float64 `json:"lo,omitempty"`
	Hi   [3]*float64 `json:"hi,omitempty"`
}

// Prop is a proportion with a 95 % Wilson interval.
type Prop struct {
	K  int     `json:"k"`
	N  int     `json:"n"`
	P  float64 `json:"p"`
	Lo float64 `json:"lo"`
	Hi float64 `json:"hi"`
}

// Rate is a count per benign host-hour with a 95 % Poisson interval.
type Rate struct {
	Count int     `json:"count"`
	Rate  float64 `json:"per_host_hour"`
	Lo    float64 `json:"lo"`
	Hi    float64 `json:"hi"`
}

// BenignFinding is a finding on benign traffic, with its reasons.
type BenignFinding struct {
	Capture  string   `json:"capture"`
	Category string   `json:"category"`
	Title    string   `json:"title"`
	Score    float64  `json:"score"`
	Severity string   `json:"severity"`
	Reasons  []string `json:"reasons"`
}

// PrevalenceRow: distinct internal clients with a series to one
// destination in one period bucket, across the benign set.
type PrevalenceRow struct {
	Destination  string `json:"destination"`
	PeriodBucket string `json:"period_bucket"`
	Clients      int    `json:"clients"`
}

// ScorerRow is one line of the v1 / v2 / RITA-like comparison.
type ScorerRow struct {
	Scorer       string   `json:"scorer"`
	Threshold    *float64 `json:"threshold,omitempty"`
	FPPerHH      *Rate    `json:"fp_per_host_hour,omitempty"`
	TPR          *Prop    `json:"tpr,omitempty"`
	WorstHeldOut string   `json:"worst_held_out_framework,omitempty"`
}

// JitterRow is one point of the detection-vs-jitter curve.
type JitterRow struct {
	Jitter string  `json:"jitter"`
	Scorer string  `json:"scorer"`
	N      int     `json:"n"`
	Mean   float64 `json:"mean_score"`
	Median float64 `json:"median_score"`
	TPR    *Prop   `json:"tpr,omitempty"`
}

// lowerTail lists metrics whose suspicious tail is low values.
var lowerTail = map[string]bool{"cv": true, "an": true, "spread": true}

// MinEventsBaseline is k for the "n ≥ k events to one destination" baseline.
const MinEventsBaseline = 20

var scorers = map[string]func(Series) float64{
	"v1":        func(s Series) float64 { return s.V1 },
	"v2":        func(s Series) float64 { return s.V2 },
	"rita_like": func(s Series) float64 { return s.RITA },
	"n_ge_k": func(s Series) float64 {
		if s.Events >= MinEventsBaseline {
			return 1
		}
		return 0
	},
}

func scorerNames() []string {
	n := make([]string, 0, len(scorers))
	for k := range scorers {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// CalibrationRows are the run's calibration examples (see Fit).
func (r *Report) CalibrationRows() []CalRow { return r.calRows }

func newReport() *Report {
	r := &Report{ReportVersion: 2}
	r.init()
	return r
}

func (r *Report) init() {
	if r.BenignQuantiles == nil {
		r.BenignQuantiles = map[string]Quantiles{}
	}
	if r.Thresholds == nil {
		r.Thresholds = map[string]float64{}
	}
	if r.Cells == nil {
		r.Cells = map[string]map[string]float64{}
	}
	if r.CellCI == nil {
		r.CellCI = map[string]map[string]Prop{}
	}
	if r.JitterTPR == nil {
		r.JitterTPR = map[string]map[string]Prop{}
	}
	if r.WorstHeldOut == nil {
		r.WorstHeldOut = map[string]string{}
	}
	if r.FPPerHostHour == nil {
		r.FPPerHostHour = map[string]float64{}
	}
	if r.FPPerHostHourCI == nil {
		r.FPPerHostHourCI = map[string]Rate{}
	}
	if r.FPBySeverity == nil {
		r.FPBySeverity = map[string]Rate{}
	}
}

var quantileLevels = [2][3]float64{{.99, .999, .9999}, {.01, .001, .0001}}

func (r *Report) summarise() {
	r.init()
	var neg, pos []Series
	for _, s := range r.Series {
		switch s.Label {
		case "benign":
			neg = append(neg, s)
		case "c2":
			pos = append(pos, s)
		}
	}
	r.BenignSeries, r.C2Series = len(neg), len(pos)
	if r.Synthetic {
		r.Banner = Banner
	}
	refuse := r.Synthetic && len(neg) < MinBenignSeries
	r.FlipGate = FlipGate{BenignSeries: len(neg), Required: MinBenignSeries}
	switch {
	case r.Synthetic:
		r.FlipGate.Reason = "synthetic-only data cannot support a default change"
	case len(neg) < MinBenignSeries:
		r.FlipGate.Reason = fmt.Sprintf("%d benign series, fewer than the %d required", len(neg), MinBenignSeries)
	default:
		r.FlipGate.Eligible = true
		r.FlipGate.Reason = "data floor met (TPR and FP rates still decide)"
	}
	switch {
	case len(neg) == 0:
		r.Notes = append(r.Notes, "no benign series: thresholds and FP rates are undefined — add benign captures")
	case refuse:
		r.Refusal = fmt.Sprintf("No operating points: this report is built only from synthetic data and has %d benign series, fewer than the %d required. "+
			"Thresholds, TPR and FP-per-host-hour at an operating point are not computed. Score distributions and the detection-vs-jitter curve (mean and median scores) are still reported.",
			len(neg), MinBenignSeries)
	case len(neg) < 10000:
		r.Notes = append(r.Notes, fmt.Sprintf("only %d benign series: the 0.9999 quantile is the sample maximum (needs ≥ 10,000 for a real 1e-4 operating point)", len(neg)))
	}
	// benign quantiles per metric
	metric := map[string]func(Series) (float64, bool){
		"cv": func(s Series) (float64, bool) { return deref(s.CV) }, "an": func(s Series) (float64, bool) { return deref(s.An) },
		"rh": func(s Series) (float64, bool) { return deref(s.Rh) }, "spread": func(s Series) (float64, bool) { return deref(s.Spread) },
	}
	for _, sc := range scorerNames() {
		f := scorers[sc]
		metric[sc] = func(s Series) (float64, bool) { return f(s), true }
	}
	for name, f := range metric {
		var v []float64
		for _, s := range neg {
			if x, ok := f(s); ok {
				v = append(v, x)
			}
		}
		if len(v) == 0 {
			continue
		}
		sort.Float64s(v)
		q := Quantiles{Tail: "upper", N: len(v)}
		lv := quantileLevels[0]
		if lowerTail[name] {
			q.Tail, lv = "lower", quantileLevels[1]
		}
		for i, p := range lv {
			q.Q[i] = stats.Quantile(v, p)
			q.Lo[i], q.Hi[i] = quantileCI(v, p)
		}
		r.BenignQuantiles[name] = q
	}
	r.summariseFindings()
	r.jitterCurve(pos, refuse)
	if refuse || len(neg) == 0 {
		r.comparison(pos)
		return
	}
	// Neyman–Pearson operating points and FP/host-hour
	for _, sc := range scorerNames() {
		q, ok := r.BenignQuantiles[sc]
		if !ok {
			continue
		}
		th := q.Q[2]
		r.Thresholds[sc] = th
		fp := 0
		for _, s := range neg {
			if scorers[sc](s) > th {
				fp++
			}
		}
		if r.BenignHostHours > 0 {
			r.FPPerHostHour[sc] = float64(fp) / r.BenignHostHours
			r.FPPerHostHourCI[sc] = rate(fp, r.BenignHostHours)
		}
	}
	// per-cell TPR (a series is detected when its score exceeds the threshold)
	byCell := map[string][]Series{}
	byFW := map[string][]Series{}
	byJit := map[string][]Series{}
	for _, s := range pos {
		byCell[s.Cell] = append(byCell[s.Cell], s)
		byFW[s.Framework] = append(byFW[s.Framework], s)
		byJit[s.Jitter] = append(byJit[s.Jitter], s)
	}
	for cell, ss := range byCell {
		r.Cells[cell] = map[string]float64{}
		r.CellCI[cell] = map[string]Prop{}
		for _, sc := range scorerNames() {
			if p, ok := r.tpr(ss, sc); ok {
				r.Cells[cell][sc] = p.P
				r.CellCI[cell][sc] = p
			}
		}
	}
	for j, ss := range byJit {
		r.JitterTPR[j] = map[string]Prop{}
		for _, sc := range scorerNames() {
			if p, ok := r.tpr(ss, sc); ok {
				r.JitterTPR[j][sc] = p
			}
		}
	}
	for _, sc := range scorerNames() {
		worst, wv := "", 2.0
		fws := make([]string, 0, len(byFW))
		for fw := range byFW {
			fws = append(fws, fw)
		}
		sort.Strings(fws)
		for _, fw := range fws {
			if p, ok := r.tpr(byFW[fw], sc); ok && p.P < wv {
				worst, wv = fw, p.P
			}
		}
		if worst != "" {
			r.WorstHeldOut[sc] = fmt.Sprintf("%s (TPR %.2f)", worst, wv)
		}
	}
	r.comparison(pos)
}

func (r *Report) tpr(ss []Series, sc string) (Prop, bool) {
	th, ok := r.Thresholds[sc]
	if !ok || len(ss) == 0 {
		return Prop{}, false
	}
	k := 0
	for _, s := range ss {
		if scorers[sc](s) > th {
			k++
		}
	}
	return wilson(k, len(ss)), true
}

// summariseFindings: FP per host-hour per severity and the top 20.
func (r *Report) summariseFindings() {
	counts := map[string]int{}
	for _, f := range r.benignFindings {
		counts[f.Severity]++
	}
	if r.BenignHostHours > 0 {
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			r.FPBySeverity[sev] = rate(counts[sev], r.BenignHostHours)
		}
	}
	all := append([]BenignFinding(nil), r.benignFindings...)
	sort.SliceStable(all, func(i, j int) bool { return all[i].Score > all[j].Score })
	if len(all) > 20 {
		all = all[:20]
	}
	r.TopBenign = all
	// prevalence
	r.Prevalence = nil
	for k, cl := range r.prevalence {
		r.Prevalence = append(r.Prevalence, PrevalenceRow{Destination: k[0], PeriodBucket: k[1], Clients: len(cl)})
	}
	sort.Slice(r.Prevalence, func(i, j int) bool {
		a, b := r.Prevalence[i], r.Prevalence[j]
		if a.Clients != b.Clients {
			return a.Clients > b.Clients
		}
		return a.Destination+a.PeriodBucket < b.Destination+b.PeriodBucket
	})
}

func (r *Report) jitterCurve(pos []Series, refuse bool) {
	byJit := map[string][]Series{}
	for _, s := range pos {
		byJit[s.Jitter] = append(byJit[s.Jitter], s)
	}
	js := make([]string, 0, len(byJit))
	for j := range byJit {
		js = append(js, j)
	}
	sort.Slice(js, func(a, b int) bool { return jitterOrder(js[a]) < jitterOrder(js[b]) })
	r.JitterCurve = nil
	for _, j := range js {
		for _, sc := range scorerNames() {
			var v []float64
			for _, s := range byJit[j] {
				v = append(v, scorers[sc](s))
			}
			sort.Float64s(v)
			row := JitterRow{Jitter: j, Scorer: sc, N: len(v), Mean: round3(mean(v)), Median: round3(stats.Quantile(v, .5))}
			if !refuse {
				if p, ok := r.tpr(byJit[j], sc); ok {
					row.TPR = &p
				}
			}
			r.JitterCurve = append(r.JitterCurve, row)
		}
	}
}

func (r *Report) comparison(pos []Series) {
	r.Comparison = nil
	for _, sc := range []string{"v1", "v2", "rita_like", "n_ge_k"} {
		row := ScorerRow{Scorer: sc, WorstHeldOut: r.WorstHeldOut[sc]}
		if th, ok := r.Thresholds[sc]; ok {
			th := th
			row.Threshold = &th
			if fp, ok := r.FPPerHostHourCI[sc]; ok {
				row.FPPerHH = &fp
			}
			if p, ok := r.tpr(pos, sc); ok {
				row.TPR = &p
			}
		}
		r.Comparison = append(r.Comparison, row)
	}
}

func jitterOrder(j string) float64 {
	var f float64
	if _, err := fmt.Sscanf(j, "%g%%", &f); err == nil {
		return f
	}
	return math.Inf(1)
}

func mean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := 0.0
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

func round3(x float64) float64 { return math.Round(x*1000) / 1000 }

func deref(p *float64) (float64, bool) {
	if p == nil {
		return 0, false
	}
	return *p, true
}

// RITALike is a clean-room approximation of a RITA-style timestamp score,
// written from the published description only (no RITA code consulted or
// copied): equal-weight mean of interval skew (1 − |Bowley|), interval
// dispersion (1 − MAD/median), hourly-histogram evenness (1 − CV of 24
// bins over the series span) and duration coverage (span / capture length).
func RITALike(times []float64, captureSec float64) float64 {
	if len(times) < 4 {
		return 0
	}
	gaps := make([]float64, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		gaps = append(gaps, times[i]-times[i-1])
	}
	sg := stats.Sorted(gaps)
	med := stats.Quantile(sg, .5)
	if med <= 0 {
		return 0
	}
	skew := 1 - math.Abs(stats.Bowley(sg))
	disp := stats.Clamp01(1 - stats.MAD(gaps, med)/med)
	span := times[len(times)-1] - times[0]
	hist := 0.0
	if span > 0 {
		var bins [24]float64
		for _, t := range times {
			k := int((t - times[0]) / span * 24)
			if k > 23 {
				k = 23
			}
			bins[k]++
		}
		var m, v float64
		for _, b := range bins {
			m += b
		}
		m /= 24
		for _, b := range bins {
			v += (b - m) * (b - m)
		}
		if m > 0 {
			hist = stats.Clamp01(1 - math.Sqrt(v/24)/m)
		}
	}
	dur := 0.0
	if captureSec > 0 {
		dur = stats.Clamp01(span / captureSec)
	}
	return math.Round((0.25*skew+0.25*disp+0.25*hist+0.25*dur)*1000) / 1000
}

// Write saves report.json, report.md, series.csv, detection_vs_jitter.csv
// and prevalence.csv into dir.
func (r *Report) Write(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), b, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(r.Markdown()), 0o644); err != nil {
		return err
	}
	opt := func(p *float64) string {
		if p == nil {
			return ""
		}
		return strconv.FormatFloat(*p, 'f', 4, 64)
	}
	ff := func(x float64, d int) string { return strconv.FormatFloat(x, 'f', d, 64) }
	rows := [][]string{{"capture", "framework", "cell", "label", "site", "key", "client", "event_model", "refused", "events",
		"period_sec", "v1", "v2", "rita_like", "cv", "an", "rh", "spread", "polarity"}}
	for _, s := range r.Series {
		rows = append(rows, []string{s.Capture, s.Framework, s.Cell, s.Label, s.Site, s.Key, s.Client, s.EventModel, s.Refused,
			strconv.Itoa(s.Events), ff(s.PeriodSec, 3), ff(s.V1, 3), ff(s.V2, 3), ff(s.RITA, 3), opt(s.CV), opt(s.An), opt(s.Rh), opt(s.Spread), s.Polarity})
	}
	if err := writeCSV(filepath.Join(dir, "series.csv"), rows); err != nil {
		return err
	}
	rows = [][]string{{"jitter", "scorer", "n", "mean_score", "median_score", "tpr", "tpr_lo", "tpr_hi"}}
	for _, j := range r.JitterCurve {
		t, lo, hi := "", "", ""
		if j.TPR != nil {
			t, lo, hi = ff(j.TPR.P, 4), ff(j.TPR.Lo, 4), ff(j.TPR.Hi, 4)
		}
		rows = append(rows, []string{j.Jitter, j.Scorer, strconv.Itoa(j.N), ff(j.Mean, 3), ff(j.Median, 3), t, lo, hi})
	}
	if err := writeCSV(filepath.Join(dir, "detection_vs_jitter.csv"), rows); err != nil {
		return err
	}
	rows = [][]string{{"destination", "period_bucket", "clients"}}
	for _, p := range r.Prevalence {
		rows = append(rows, []string{p.Destination, p.PeriodBucket, strconv.Itoa(p.Clients)})
	}
	return writeCSV(filepath.Join(dir, "prevalence.csv"), rows)
}

func writeCSV(path string, rows [][]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	_ = w.WriteAll(rows)
	if err := w.Error(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// safeUnmarshal is yaml.Unmarshal that turns a decoder panic into an
// error (goccy/go-yaml v1.19.2 panics on some malformed input, e.g. a
// tagged mapping where a sequence is expected; found by fuzzing).
func safeUnmarshal(b []byte, v any, opts ...yaml.DecodeOption) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("yaml: malformed input (%v)", r)
		}
	}()
	return yaml.UnmarshalWithOptions(b, v, opts...)
}
