package eval

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"c2parser/internal/engine"
	"c2parser/internal/synth"
)

// v9 rev 2 Phase 1.4 wiring gate: `c2parser eval` runs end-to-end on a
// generated corpus and produces per-cell tables. Synthetic results test
// the plumbing; they never set thresholds.
func TestEvalOnSyntheticCorpus(t *testing.T) {
	if testing.Short() {
		t.Skip("corpus")
	}
	files, _ := filepath.Glob("../../corpus/scenarios/*.yaml")
	dir := t.TempDir()
	var rows []synth.ManifestEntry
	for _, f := range files {
		if !strings.Contains(f, "gate-") && !strings.Contains(f, "benign-") {
			continue
		}
		sc, err := synth.LoadScenario(f)
		if err != nil {
			t.Fatal(err)
		}
		me, err := synth.WriteFile(sc, dir)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, *me)
	}
	mp := filepath.Join(dir, "manifest.yaml")
	if err := synth.WriteManifest(mp, rows); err != nil {
		t.Fatal(err)
	}
	m, err := LoadManifest(mp)
	if err != nil {
		t.Fatalf("eval cannot load the synthgen manifest: %v", err)
	}
	if len(m.Captures) != len(rows) {
		t.Fatalf("%d captures loaded, %d written", len(m.Captures), len(rows))
	}
	rep, err := Run(m, engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var c2, benign int
	for _, s := range rep.Series {
		switch s.Label {
		case "c2":
			c2++
		case "benign":
			benign++
		}
	}
	if c2 == 0 || benign == 0 {
		t.Fatalf("labels not joined: %d c2, %d benign series", c2, benign)
	}
	// v10a 1.4 refusal rule: a synthetic-only report keeps the banner and,
	// with < 1000 benign series, emits no operating points — in words.
	if !rep.Synthetic || rep.Banner != Banner {
		t.Errorf("synthgen corpus not recognised as synthetic-only (banner %q)", rep.Banner)
	}
	if rep.BenignSeries >= MinBenignSeries {
		t.Fatalf("corpus has %d benign series; the refusal case needs < %d", rep.BenignSeries, MinBenignSeries)
	}
	if rep.Refusal == "" || len(rep.Thresholds) != 0 || len(rep.Cells) != 0 || len(rep.JitterTPR) != 0 || len(rep.FPPerHostHour) != 0 {
		t.Errorf("operating points emitted on a synthetic-only report: refusal %q thresholds %v cells %d", rep.Refusal, rep.Thresholds, len(rep.Cells))
	}
	if len(rep.JitterCurve) == 0 {
		t.Error("no detection-vs-jitter curve")
	}
	for _, j := range rep.JitterCurve {
		if j.TPR != nil {
			t.Errorf("TPR in the jitter curve of a refused report: %+v", j)
		}
	}
	// mutation: the same series without the synthetic marking get
	// operating points (the refusal is what removed them)
	real := *rep
	real.Synthetic, real.Refusal, real.Banner, real.Notes = false, "", "", nil
	real.Thresholds, real.Cells, real.CellCI, real.JitterTPR, real.FPPerHostHour, real.FPPerHostHourCI = nil, nil, nil, nil, nil, nil
	real.summarise()
	if len(real.Thresholds) == 0 || len(real.Cells) == 0 {
		t.Error("mutation: no operating points without the synthetic marking — the refusal is not what suppresses them")
	}
	for cell, tpr := range real.Cells {
		if !strings.HasPrefix(cell, "synth:gate-") {
			t.Errorf("unexpected cell %q", cell)
		}
		if _, ok := tpr["v2"]; !ok {
			t.Errorf("cell %s has no v2 TPR", cell)
		}
	}
	if rep.BenignHostHours <= 0 {
		t.Error("no benign host-hours")
	}
	out := filepath.Join(dir, "out")
	if err := rep.Write(out); err != nil {
		t.Fatal(err)
	}
	md, _ := os.ReadFile(filepath.Join(out, "report.md"))
	if !strings.Contains(string(md), Banner) || !strings.Contains(string(md), "No operating points: this report is built only from synthetic data") {
		t.Errorf("report.md lacks the banner or the plain-words refusal")
	}
	for _, f := range []string{"report.json", "series.csv", "detection_vs_jitter.csv", "prevalence.csv"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	t.Logf("%d c2 / %d benign series, %d cells (unrefused), %.1f benign host-hours", c2, benign, len(real.Cells), rep.BenignHostHours)
}
