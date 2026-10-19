package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"c2parser/internal/engine"
	"c2parser/internal/synth"
)

// v9c D3: fleet-capped findings stay visible — in JSON at their capped
// score with the annotation, and in text at the default -min-score (0.2).
func TestCappedFindingsVisible(t *testing.T) {
	sc, err := synth.LoadScenario("../../corpus/scenarios/gate-fleet3-https-60s.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	me, err := synth.WriteFile(sc, dir)
	if err != nil {
		t.Fatal(err)
	}
	res, err := engine.AnalyzeFile(filepath.Join(dir, me.Path), engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var jb bytes.Buffer
	if err := JSON(&jb, []*engine.Result{res}, Options{MinScore: 0.2}); err != nil {
		t.Fatal(err)
	}
	var out []engine.Result
	if err := json.Unmarshal(jb.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range out[0].Findings {
		if f.Score == engine.TimingOnlyCap && strings.Contains(strings.Join(f.Evidence, " "), "fleet-wide periodic destination (3 of 3 hosts)") {
			n++
		}
	}
	if n != 3 {
		t.Errorf("JSON: %d capped fleet findings with the annotation, want 3", n)
	}
	var tb bytes.Buffer
	Text(&tb, res, Options{MinScore: 0.2})
	if c := strings.Count(tb.String(), "fleet-wide periodic destination"); c < 3 {
		t.Errorf("text at -min-score 0.2 shows %d fleet annotations, want 3", c)
	}
	var hb bytes.Buffer
	Text(&hb, res, Options{MinScore: 0.4})
	if strings.Contains(hb.String(), "fleet-wide") {
		t.Error("text at -min-score 0.4 still shows capped findings")
	}
	_ = os.Remove(filepath.Join(dir, me.Path))
}
