package eval

import (
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"c2parser/internal/engine"
	"c2parser/internal/pcapio"
	"c2parser/internal/stats"
)

// Options control a run.
type Options struct {
	Jobs     int       // concurrent units (engine runs); ≤ 1 = sequential
	Progress io.Writer // optional per-unit progress lines
}

// Run evaluates every capture with base config cfg (TimingV2 is forced
// on) — sequentially; see RunWith.
func Run(m *Manifest, cfg engine.Config) (*Report, error) { return RunWith(m, cfg, Options{Jobs: 1}) }

type unitOut struct {
	info     UnitInfo
	series   []Series
	findings []BenignFinding
	prev     map[[2]string]map[string]bool
	cal      []CalRow
	hh       float64
	err      error
}

// RunWith evaluates the manifest with up to opts.Jobs units in parallel.
// Results are merged in manifest order, so output does not depend on Jobs.
func RunWith(m *Manifest, cfg engine.Config, opts Options) (*Report, error) {
	units, err := m.Resolve()
	if err != nil {
		return nil, err
	}
	cfg.TimingV2 = true
	jobs := max(1, opts.Jobs)
	outs := make([]unitOut, len(units))
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, jobs)
	for i := range units {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			t0 := time.Now()
			outs[i] = runUnit(m, units[i], cfg)
			if opts.Progress != nil {
				mu.Lock()
				fmt.Fprintf(opts.Progress, "eval: %s (%s) %d series in %.1fs\n", units[i].Name, units[i].Capture.Role, len(outs[i].series), time.Since(t0).Seconds())
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	rep := newReport()
	rep.Synthetic = len(units) > 0
	rep.prevalence = map[[2]string]map[string]bool{}
	for i, o := range outs {
		if o.err != nil {
			return nil, fmt.Errorf("%s: %w", units[i].Name, o.err)
		}
		if !units[i].Capture.isSynthetic(m) {
			rep.Synthetic = false
		}
		rep.Units = append(rep.Units, o.info)
		rep.Series = append(rep.Series, o.series...)
		rep.benignFindings = append(rep.benignFindings, o.findings...)
		rep.calRows = append(rep.calRows, o.cal...)
		rep.BenignHostHours += o.hh
		for k, cl := range o.prev {
			if rep.prevalence[k] == nil {
				rep.prevalence[k] = map[string]bool{}
			}
			for c := range cl {
				rep.prevalence[k][c] = true
			}
		}
		if e := o.info.ExpectedHostHours; e > 0 && (o.hh < 0.9*e || o.hh > 1.1*e) {
			rep.Notes = append(rep.Notes, fmt.Sprintf("%s: measured %.1f benign host-hours, manifest expects %.1f (missing rotation segment, sensor gap or wrong internal CIDRs?)", o.info.Name, o.hh, e))
		}
		if j := o.info.Join; j != nil {
			l := units[i].Capture.Labels
			if l.MinJoin > 0 && j.Rate < l.MinJoin {
				return nil, fmt.Errorf("%s: Zeek UID join matched %.1f %% < min_join %.1f %%", o.info.Name, 100*j.Rate, 100*l.MinJoin)
			}
			if j.Positives > 0 && j.PosMatched < j.Positives {
				rep.Notes = append(rep.Notes, fmt.Sprintf("%s: %d of %d labelled C2 connections did not join", o.info.Name, j.Positives-j.PosMatched, j.Positives))
			}
		}
	}
	rep.summarise()
	return rep, nil
}

// labeler assigns series and finding labels for one unit.
type labeler struct {
	role    string
	eps     []Endpoint
	windows []window
	start   float64 // capture start (unix s); series times are relative to it
}

func epMatch(ep Endpoint, client, key string, names ...string) bool {
	if ep.Client != "" && ep.Client != client {
		return false
	}
	if ep.Server == "" {
		return true
	}
	if strings.Contains(key+"|", "|"+ep.Server+"|") {
		return true
	}
	for _, n := range names {
		if n == ep.Server {
			return true
		}
	}
	return false
}

func (l *labeler) positive(client, key string, times []float64, names ...string) bool {
	for _, ep := range l.eps {
		if epMatch(ep, client, key, names...) {
			return true
		}
	}
	for _, w := range l.windows {
		if !epMatch(w.ep, client, key, names...) {
			continue
		}
		if times == nil { // a finding: match on endpoints alone
			return true
		}
		for _, t := range times {
			if at := l.start + t; at >= w.start && at <= w.end {
				return true
			}
		}
	}
	return false
}

func (l *labeler) label(client, key string, times []float64) string {
	switch {
	case l.role == RoleBenign:
		return "benign"
	case l.positive(client, key, times):
		return "c2"
	case l.role == RoleMixed:
		return "benign"
	}
	return "background"
}

func runUnit(m *Manifest, u Unit, base engine.Config) (o unitOut) {
	c := u.Capture
	cfg := base
	if len(m.internal) > 0 {
		cfg.Internal = m.internal
	}
	if len(c.internal) > 0 {
		cfg.Internal = c.internal
	}
	src := LabelNone
	if c.Labels != nil {
		src = c.Labels.Source
	}
	cfg.RecordConns = src == LabelZeekUID
	e := engine.New(cfg)
	for _, f := range u.Files {
		r, err := pcapio.Open(f)
		if err != nil {
			o.err = err
			return
		}
		err = e.Ingest(r)
		r.Close()
		if err != nil {
			o.err = fmt.Errorf("%s: %w", filepath.Base(f), err)
			return
		}
	}
	res := e.Finish()
	o.info = UnitInfo{Name: u.Name, Role: c.Role, Files: len(u.Files), DurationSec: res.DurationSec,
		ExpectedHostHours: c.ExpectedHostHours, LabelSource: src, Findings: len(res.Findings)}
	lb := &labeler{role: c.Role}
	if t, err := time.Parse(time.RFC3339Nano, res.Start); err == nil {
		lb.start = float64(t.UnixNano()) / 1e9
	}
	meta := *c
	switch src {
	case LabelPerCapture:
		lb.eps = c.Labels.C2
	case LabelTimeWindow:
		lb.windows = c.windows
	case LabelZeekUID:
		cols := c.Labels.Columns.withDefaults(m.Columns)
		zl, err := loadZeekLabels(c.Labels, cols, res.Conns)
		if err != nil {
			o.err = err
			return
		}
		lb.eps = zl.endpoints
		st := zl.stats
		o.info.Join = &st
		// per-cell metadata from the label file fills what the manifest left blank
		if meta.Framework == "" {
			meta.Framework = zl.majority("framework")
		}
		if meta.Transport == "" {
			meta.Transport = zl.majority("transport")
		}
		if meta.Sleep == 0 {
			fmt.Sscanf(zl.majority("sleep"), "%g", &meta.Sleep)
		}
		if meta.Jitter == 0 {
			fmt.Sscanf(strings.TrimSuffix(zl.majority("jitter"), "%"), "%g", &meta.Jitter)
		}
	}
	o.info.Positives = len(lb.eps) + len(lb.windows)
	cell, jit := meta.cell(), meta.jitterCell()
	// series
	clients := map[string]bool{}
	o.prev = map[[2]string]map[string]bool{}
	name := u.Name
	for _, ts := range res.Timing {
		cl := seriesClient(ts.Key)
		lab := lb.label(cl, ts.Key, ts.Times())
		s := Series{Capture: name, Framework: meta.Framework, Label: lab, Site: ts.Site, Key: ts.Key, Client: cl,
			EventModel: ts.EventModel, Refused: ts.Refused, V2: ts.V2Score, Events: len(ts.Times()), RITA: RITALike(ts.Times(), res.DurationSec)}
		if lab == "c2" {
			s.Cell, s.Jitter = cell, jit
		}
		if ts.V1Score != nil {
			s.V1 = *ts.V1Score
		}
		if t := ts.Timing; t != nil {
			s.CV, s.An, s.Rh, s.Spread, s.Polarity, s.PeriodSec = t.CV, t.An, t.Rh, t.Spread, t.Polarity, t.PeriodSec
			if s.Refused == "" {
				s.Refused = t.Refused
			}
		}
		if lab == "benign" {
			clients[cl] = true
			if a, err := netip.ParseAddr(cl); err == nil && isInternal(cfg.Internal, a) {
				k := [2]string{seriesDest(ts.Key, cl), periodBucket(s.PeriodSec)}
				if o.prev[k] == nil {
					o.prev[k] = map[string]bool{}
				}
				o.prev[k][cl] = true
			}
		}
		o.series = append(o.series, s)
	}
	// Benign host-hours: the clients with benign-labelled series (v8a
	// review #3: in a mixed capture, only the background clients count).
	o.hh = float64(len(clients)) * res.DurationSec / 3600
	o.info.BenignHostHours = round3(o.hh)
	o.info.Series = len(o.series)
	o.cal = calibrationRows(c.Role, meta.Framework, lb, res.Findings, o.series)
	// benign findings
	if c.Role != RoleC2 {
		for _, f := range res.Findings {
			if f.Score < 0.2 {
				continue
			}
			if c.Role == RoleMixed && lb.positive(f.Client, "|"+f.Server+"|", nil, append(f.ServerNames, f.Server)...) {
				continue
			}
			o.findings = append(o.findings, BenignFinding{Capture: name, Category: f.Category, Title: f.Title, Score: f.Score,
				Severity: f.Severity, Reasons: reasons(f.Signals)})
		}
	}
	return o
}

var defaultInternal, _ = engine.ParsePrefixes(engine.DefaultInternal)

func isInternal(ps []netip.Prefix, a netip.Addr) bool {
	if len(ps) == 0 {
		ps = defaultInternal
	}
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// reasons are a finding's top signals as "name (contribution)".
func reasons(sigs []stats.Signal) []string {
	ss := append([]stats.Signal(nil), sigs...)
	stats.SortSignals(ss)
	var out []string
	for _, s := range ss {
		if s.Contribution() <= 0 {
			continue
		}
		out = append(out, fmt.Sprintf("%s %.2f", s.Name, s.Contribution()))
		if len(out) == 4 {
			break
		}
	}
	return out
}

// seriesClient extracts the client IP from a series key.
func seriesClient(key string) string {
	for _, part := range strings.Split(key, "|") {
		if a, err := netip.ParseAddr(part); err == nil {
			return a.String()
		}
	}
	return ""
}

// seriesDest is the key's first part after the client: the server IP or
// the name for name-keyed series.
func seriesDest(key, client string) string {
	parts := strings.Split(key, "|")
	for i, p := range parts {
		if p == client && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return key
}

var periodBuckets = []struct {
	max  float64
	name string
}{{0, "none"}, {10, "≤10s"}, {60, "10s–1m"}, {300, "1–5m"}, {900, "5–15m"}, {3600, "15m–1h"}, {6 * 3600, "1–6h"}}

func periodBucket(p float64) string {
	if p <= 0 {
		return "none"
	}
	for _, b := range periodBuckets[1:] {
		if p <= b.max {
			return b.name
		}
	}
	return ">6h"
}

func (c Capture) cell() string {
	if c.Role == RoleBenign {
		return ""
	}
	sleep := "unknown"
	if c.Sleep > 0 {
		sleep = fmt.Sprintf("%gs", c.Sleep)
	}
	return fmt.Sprintf("%s/%s/%s/%s", orUnknown(c.Framework), orUnknown(c.Transport), sleep, c.jitterCell())
}

func (c Capture) jitterCell() string {
	if c.Jitter > 0 {
		return fmt.Sprintf("%g%%", c.Jitter)
	}
	if c.Sleep > 0 && c.Framework != "" { // a declared cell with jitter 0
		return "0%"
	}
	return "unknown"
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// calibrationRows turns a unit's findings into calibration examples:
// positives (findings on labelled C2 endpoints) and negatives (findings
// in benign or mixed captures off the labelled endpoints); a C2 series
// whose client has no positive finding adds an all-zero positive row, so
// misses count. Background in role-c2 captures is left out.
func calibrationRows(role, framework string, lb *labeler, fs []engine.Finding, series []Series) []CalRow {
	var out []CalRow
	hit := map[string]bool{}
	for _, f := range fs {
		if len(f.Families) == 0 {
			continue
		}
		x := map[string]float64{}
		for k, v := range f.Families {
			x[k] = v
		}
		pos := role != RoleBenign && lb.positive(f.Client, "|"+f.Server+"|", nil, append(f.ServerNames, f.Server)...)
		switch {
		case pos:
			hit[f.Client] = true
			out = append(out, CalRow{Group: framework, Label: 1, X: x, Product: f.Score})
		case role != RoleC2:
			out = append(out, CalRow{Label: 0, X: x, Product: f.Score})
		}
	}
	for _, s := range series {
		if s.Label == "c2" && !hit[s.Client] {
			hit[s.Client] = true
			out = append(out, CalRow{Group: framework, Label: 1, X: map[string]float64{}, Product: 0})
		}
	}
	return out
}
