package eval

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"c2parser/internal/engine"
	"c2parser/internal/perturb"
	"c2parser/internal/synth"
)

func writeManifest(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// v10a 1.1: strict schema. Each case must be rejected at load time, with
// a message naming the problem.
func TestManifestStrict(t *testing.T) {
	bad := map[string]string{
		"unknown top-level key":   "version: 2\nthreshold: 0.5\ncaptures:\n  - {path: a.pcap, role: benign}\n",
		"unknown capture key":     "version: 2\ncaptures:\n  - {path: a.pcap, role: benign, lable: x}\n",
		"unknown labels key":      "version: 2\ncaptures:\n  - {path: a.pcap, role: c2, labels: {source: per-capture, c2: [{client: 10.0.0.1}], extra: 1}}\n",
		"unknown v1 key":          "captures:\n  - {path: a.pcap, benign: true, polarty: x}\n",
		"no captures":             "version: 2\n",
		"future version":          "version: 3\ncaptures:\n  - {path: a.pcap, role: benign}\n",
		"bad role":                "version: 2\ncaptures:\n  - {path: a.pcap, role: positive}\n",
		"c2 without labels":       "version: 2\ncaptures:\n  - {path: a.pcap, role: c2}\n",
		"benign with labels":      "version: 2\ncaptures:\n  - {path: a.pcap, role: benign, labels: {source: per-capture, c2: [{client: 10.0.0.1}]}}\n",
		"zeek without conn_log":   "version: 2\ncaptures:\n  - {path: a.pcap, role: mixed, labels: {source: zeek-uid}}\n",
		"per-capture without c2":  "version: 2\ncaptures:\n  - {path: a.pcap, role: c2, labels: {source: per-capture}}\n",
		"empty endpoint":          "version: 2\ncaptures:\n  - {path: a.pcap, role: c2, labels: {source: per-capture, c2: [{}]}}\n",
		"window ends first":       "version: 2\ncaptures:\n  - {path: a.pcap, role: c2, labels: {source: time-window, windows: [{start: 200, end: 100}]}}\n",
		"window bad time":         "version: 2\ncaptures:\n  - {path: a.pcap, role: c2, labels: {source: time-window, windows: [{start: yesterday, end: 100}]}}\n",
		"bad label source":        "version: 2\ncaptures:\n  - {path: a.pcap, role: c2, labels: {source: guess}}\n",
		"bad CIDR":                "version: 2\ninternal: [10.0.0.0/33]\ncaptures:\n  - {path: a.pcap, role: benign}\n",
		"host-hours on c2":        "version: 2\ncaptures:\n  - {path: a.pcap, role: c2, expected_host_hours: 5, labels: {source: per-capture, c2: [{client: 10.0.0.1}]}}\n",
		"v1 keys in v2":           "version: 2\ncaptures:\n  - {path: a.pcap, role: benign, benign: true}\n",
		"v2 keys in v1":           "captures:\n  - {path: a.pcap, role: benign}\n",
		"v1 positive without c2":  "captures:\n  - {path: a.pcap, framework: x}\n",
		"jitter not a percentage": "version: 2\ncaptures:\n  - {path: a.pcap, role: benign, jitter: 130}\n",
		"bad glob":                "version: 2\ncaptures:\n  - {path: 'a[.pcap', role: benign}\n",
		"min_join out of range":   "version: 2\ncaptures:\n  - {path: a.pcap, role: mixed, labels: {source: zeek-uid, conn_log: c.log, min_join: 99}}\n",
		"type mismatch":           "version: 2\ncaptures:\n  - {path: a.pcap, role: benign, sleep: soon}\n",
	}
	for name, body := range bad {
		if _, err := ParseManifest([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	good := map[string]string{
		"v1 benign":   "captures:\n  - {path: a.pcap, licence: own, benign: true}\n",
		"v1 positive": "captures:\n  - path: a.pcap\n    framework: havoc\n    c2: [{client: 10.0.0.1, server: 192.0.2.1}]\n",
		"v1 synthgen": "captures:\n  - {path: a.pcap, licence: own, framework: 'synth:x', transport: udp, sleep: 0, jitter: 0, polarity: '', tasking: 'no', benign: true, scenario: x, seed: 1, shapes: [a], sha256: ab}\n",
		"v2 all sources": `version: 2
name: all
internal: [10.0.0.0/8]
columns: {uid: flow_id}
captures:
  - {path: 'b/*.pcap', role: benign, rotated: true, expected_host_hours: 48}
  - {path: c.pcap, role: c2, labels: {source: per-capture, c2: [{client: 10.0.0.1, server: c2.example}]}}
  - {path: d.pcap, role: mixed, internal: [192.168.0.0/16], labels: {source: zeek-uid, conn_log: 'd/conn.*.log.gz', label_file: d/labels.jsonl, positive: [malicious], columns: {label: verdict}}}
  - {path: e.pcap, role: c2, labels: {source: time-window, windows: [{start: '2024-03-25T12:00:00Z', end: 1711371600, client: 10.0.0.5}]}}
`,
	}
	for name, body := range good {
		m, err := ParseManifest([]byte(body))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		for _, c := range m.Captures {
			if c.Role == "" {
				t.Errorf("%s: role not normalised", name)
			}
		}
	}
	m, _ := ParseManifest([]byte(good["v1 positive"]))
	if c := m.Captures[0]; c.Role != RoleC2 || c.Labels == nil || c.Labels.Source != LabelPerCapture || len(c.Labels.C2) != 1 {
		t.Errorf("v1 positive not normalised: %+v", c)
	}
}

// Missing files are errors when the manifest is resolved for a run, not
// at load (a manifest can be checked away from the data).
func TestManifestMissingFilesAtRun(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a.pcap"), []byte("x"), 0o644)
	cases := map[string]string{
		"missing file":       "version: 2\ncaptures:\n  - {path: nope.pcap, role: benign}\n",
		"empty glob":         "version: 2\ncaptures:\n  - {path: 'segs/*.pcap', role: benign}\n",
		"missing conn_log":   "version: 2\ncaptures:\n  - {path: a.pcap, role: mixed, labels: {source: zeek-uid, conn_log: conn.log}}\n",
		"missing label file": "version: 2\ncaptures:\n  - {path: a.pcap, role: mixed, labels: {source: zeek-uid, conn_log: a.pcap, label_file: l.jsonl}}\n",
	}
	for name, body := range cases {
		m, err := LoadManifest(writeManifest(t, dir, body))
		if err != nil {
			t.Errorf("%s: load failed (should only fail at run): %v", name, err)
			continue
		}
		if _, err := RunWith(m, engine.Config{}, Options{}); err == nil {
			t.Errorf("%s: run accepted", name)
		}
	}
}

// Time-window labels: the series of the windowed endpoint inside the
// window is c2; outside the window, and other endpoints, are background.
func TestManifestTimeWindow(t *testing.T) {
	dir := t.TempDir()
	sc, err := synth.LoadScenario("../../corpus/scenarios/gate-single-https-new-conn-60s.yaml")
	if err != nil {
		t.Fatal(err)
	}
	me, err := synth.WriteFile(sc, dir)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2024, 3, 25, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		from, to time.Time
		want     string
	}{{start, start.Add(24 * time.Hour), "c2"}, {start.Add(-2 * time.Hour), start.Add(-time.Hour), "background"}} {
		body := "version: 2\nsynthetic: true\ncaptures:\n  - path: " + me.Path + "\n    role: c2\n    labels:\n      source: time-window\n      windows: [{start: '" +
			c.from.Format(time.RFC3339) + "', end: '" + c.to.Format(time.RFC3339) + "', client: " + me.C2[0].Client + "}]\n"
		m, err := LoadManifest(writeManifest(t, dir, body))
		if err != nil {
			t.Fatal(err)
		}
		rep, err := Run(m, engine.Config{})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]int{}
		for _, s := range rep.Series {
			got[s.Label]++
		}
		if got[c.want] == 0 || len(got) != 1 {
			t.Errorf("window %s–%s: labels %v, want all %s", c.from, c.to, got, c.want)
		}
	}
}

// v10a 1.3 gate: a synthetic 20-host 6-hour benign set, written as three
// rotated segments, runs end to end with -j in under 2 minutes; the
// report carries FP per host-hour per severity, quantiles with intervals,
// the top benign findings and prevalence. Mutation: without rotated: true
// the segments are scored as separate captures, the series split, and
// every segment falls short of the expected host-hours.
func TestBenignIntakeGate(t *testing.T) {
	if testing.Short() {
		t.Skip("benign gate")
	}
	dir := t.TempDir()
	sc, err := synth.LoadScenario("testdata/benign-20host-6h.yaml")
	if err != nil {
		t.Fatal(err)
	}
	me, err := synth.WriteFile(sc, dir)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := perturb.Read(filepath.Join(dir, me.Path))
	if err != nil {
		t.Fatal(err)
	}
	perturb.SortByTime(pk)
	segs := filepath.Join(dir, "segs")
	_ = os.MkdirAll(segs, 0o755)
	n := (len(pk) + 2) / 3
	for i := 0; i < 3; i++ {
		lo, hi := i*n, min((i+1)*n, len(pk))
		if err := perturb.Write(filepath.Join(segs, "benign_0000"+string(rune('1'+i))+".pcap"), pk[lo:hi]); err != nil {
			t.Fatal(err)
		}
	}
	models, err := synth.LoadScenario("../../corpus/scenarios/benign-models.yaml")
	if err != nil {
		t.Fatal(err)
	}
	mm, _ := synth.WriteFile(models, dir)
	run := func(rotated bool) (*Report, time.Duration) {
		body := "version: 2\nname: benign gate\nsynthetic: true\ncaptures:\n" +
			"  - {path: 'segs/benign_*.pcap', role: benign, rotated: " + map[bool]string{true: "true", false: "false"}[rotated] + ", expected_host_hours: 120}\n" +
			"  - {path: " + mm.Path + ", role: benign}\n"
		m, err := LoadManifest(writeManifest(t, dir, body))
		if err != nil {
			t.Fatal(err)
		}
		t0 := time.Now()
		rep, err := RunWith(m, engine.Config{}, Options{Jobs: 4})
		if err != nil {
			t.Fatal(err)
		}
		return rep, time.Since(t0)
	}
	rep, took := run(true)
	t.Logf("20 hosts × 6 h (%d packets, 3 segments) + benign-models: %d series, %.1f host-hours in %s", len(pk), len(rep.Series), rep.BenignHostHours, took)
	if took > 2*time.Minute {
		t.Errorf("benign run took %s (gate: < 2 min)", took)
	}
	u := rep.Units[0]
	if u.Files != 3 || u.DurationSec < 5.5*3600 || u.BenignHostHours < 108 || u.BenignHostHours > 132 {
		t.Errorf("rotated unit %+v", u)
	}
	for _, note := range rep.Notes {
		if strings.Contains(note, "expects") {
			t.Errorf("unexpected host-hours note: %s", note)
		}
	}
	if len(rep.FPBySeverity) != 4 {
		t.Errorf("FP per severity: %+v", rep.FPBySeverity)
	}
	for sev, r := range rep.FPBySeverity {
		if r.Hi <= r.Rate && r.Count > 0 || r.Hi <= 0 {
			t.Errorf("%s: no interval %+v", sev, r)
		}
	}
	q := rep.BenignQuantiles["v2"]
	if q.N == 0 || q.Lo[0] == nil || q.Hi[2] != nil {
		t.Errorf("v2 quantile intervals %+v (the 1e-4 upper bound cannot exist with n=%d)", q, q.N)
	}
	if len(rep.TopBenign) == 0 || len(rep.TopBenign) > 20 {
		t.Errorf("top benign findings: %d", len(rep.TopBenign))
	}
	for _, f := range rep.TopBenign {
		if len(f.Reasons) == 0 {
			t.Errorf("benign finding without reasons: %+v", f)
		}
	}
	top := map[string]int{}
	for _, p := range rep.Prevalence {
		if p.Clients > top[p.Destination] {
			top[p.Destination] = p.Clients
		}
	}
	most := 0
	for _, n := range top {
		most = max(most, n)
	}
	if most < 20 {
		t.Errorf("prevalence: no fleet-wide destination (20 clients): %v", top)
	}
	if rep.Refusal == "" {
		t.Error("synthetic-only benign set with < 1000 series emitted operating points")
	}
	out := filepath.Join(dir, "out")
	if err := rep.Write(out); err != nil {
		t.Fatal(err)
	}
	md, _ := os.ReadFile(filepath.Join(out, "report.md"))
	for _, want := range []string{"Benign findings per host-hour", "Destination prevalence", "Benign quantiles", "(+2 rotated)"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("report.md lacks %q", want)
		}
	}

	split, _ := run(false)
	notes := 0
	for _, n := range split.Notes {
		if strings.Contains(n, "expects 120.0") {
			notes++
		}
	}
	if len(split.Units) != 4 || notes != 3 || len(split.Series) <= len(rep.Series) {
		t.Errorf("mutation rotated=false: %d units, %d host-hour notes, %d vs %d series", len(split.Units), notes, len(split.Series), len(rep.Series))
	}
}

// Real-data runs (skip unless the env vars point at the data). Each
// directory holds a manifest.yaml written per docs/datasets/*.md.
func TestTQHManifest(t *testing.T)    { envRun(t, "C2PARSER_TQH") }
func TestBenignManifest(t *testing.T) { envRun(t, "C2PARSER_BENIGN") }

func envRun(t *testing.T, env string) {
	dir := os.Getenv(env)
	if dir == "" {
		t.Skipf("%s not set", env)
	}
	m, err := LoadManifest(filepath.Join(dir, "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := RunWith(m, engine.Config{}, Options{Jobs: 4, Progress: os.Stderr})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range rep.Units {
		if j := u.Join; j != nil {
			t.Logf("%s: join %+v", u.Name, *j)
			if j.Rate < 0.95 {
				t.Errorf("%s: Zeek join %.3f < 0.95 — check the column mapping", u.Name, j.Rate)
			}
		}
	}
	out := filepath.Join(dir, "eval-out") // beside the data, never in the repo
	if err := rep.Write(out); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d series (%d c2, %d benign), %.1f benign host-hours; report in %s", len(rep.Series), rep.C2Series, rep.BenignSeries, rep.BenignHostHours, out)
}

// The shipped example manifest parses under the strict schema.
func TestExampleManifestParses(t *testing.T) {
	b, err := os.ReadFile("../../docs/eval-manifest.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManifest(b); err != nil {
		t.Fatal(err)
	}
}
