package eval

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"c2parser/internal/engine"
	"c2parser/internal/pcapio"
	"c2parser/internal/perturb"
	"c2parser/internal/synth"
)

// joinFixture generates the gate scenarios with a Zeek conn.log and label
// file per capture (as `synthgen -zeek` does) and returns a v2 manifest
// using the zeek-uid label source on capture glob pcapGlob.
func joinFixture(t *testing.T, dir string) []*synth.ManifestEntry {
	t.Helper()
	files, _ := filepath.Glob("../../corpus/scenarios/*.yaml")
	var rows []*synth.ManifestEntry
	for _, f := range files {
		sc, err := synth.LoadScenario(f)
		if err != nil {
			t.Fatal(err)
		}
		me, err := synth.WriteFile(sc, dir)
		if err != nil {
			t.Fatal(err)
		}
		r, err := pcapio.Open(filepath.Join(dir, me.Path))
		if err != nil {
			t.Fatal(err)
		}
		conns, err := synth.ZeekConns(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		base := strings.TrimSuffix(me.Path, ".pcap")
		var b, l bytes.Buffer
		_ = synth.WriteZeekTSV(&b, conns)
		_ = synth.WriteLabels(&l, synth.LabelConns(conns, me))
		_ = os.WriteFile(filepath.Join(dir, base+".conn.log"), b.Bytes(), 0o644)
		_ = os.WriteFile(filepath.Join(dir, base+".labels.jsonl"), l.Bytes(), 0o644)
		rows = append(rows, me)
	}
	if len(rows) < 10 {
		t.Fatalf("only %d gate scenarios", len(rows))
	}
	return rows
}

func joinManifest(t *testing.T, dir, pcapDir string, rows []*synth.ManifestEntry) string {
	var b strings.Builder
	b.WriteString("version: 2\nsynthetic: true\ncaptures:\n")
	for _, me := range rows {
		base := strings.TrimSuffix(me.Path, ".pcap")
		role := "mixed" // benign scenarios too: every connection takes part in the join
		fmt.Fprintf(&b, "  - path: %s\n    role: %s\n", filepath.Join(pcapDir, me.Path), role)
		if role == "mixed" {
			fmt.Fprintf(&b, "    labels:\n      source: zeek-uid\n      conn_log: %s.conn.log\n      label_file: %s.labels.jsonl\n      positive: [c2]\n      columns: {framework: framework, transport: transport, sleep: sleep, jitter: jitter}\n",
				filepath.Join(dir, base), filepath.Join(dir, base))
		}
	}
	p := filepath.Join(dir, "m-"+filepath.Base(pcapDir)+".yaml")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func joinTotals(rep *Report) (js JoinStats) {
	for _, u := range rep.Units {
		if j := u.Join; j != nil {
			js.Zeek += j.Zeek
			js.Matched += j.Matched
			js.UnmatchedZeek += j.UnmatchedZeek
			js.UnmatchedC2P += j.UnmatchedC2P
			js.Ambiguous += j.Ambiguous
			js.Positives += j.Positives
			js.PosMatched += j.PosMatched
		}
	}
	if js.Zeek > 0 {
		js.Rate = float64(js.Matched) / float64(js.Zeek)
	}
	return js
}

// v10a 1.2 gate: a synthetic Zeek conn.log written beside each synthgen
// corpus scenario joins at 100 %; after perturb drop 0.01 + jitter 0.5 s
// (applied to the pcap only — the conn.log is the original ground truth)
// at ≥ 99 %. Labels reach the series. Mutation: with a 10 ms start
// tolerance the damaged join falls below 99 %.
func TestZeekJoinGate(t *testing.T) {
	if testing.Short() {
		t.Skip("corpus")
	}
	dir := t.TempDir()
	rows := joinFixture(t, dir)
	run := func(m string) *Report {
		man, err := LoadManifest(m)
		if err != nil {
			t.Fatal(err)
		}
		rep, err := RunWith(man, engine.Config{}, Options{Jobs: 4})
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	clean := run(joinManifest(t, dir, dir, rows))
	js := joinTotals(clean)
	t.Logf("clean: %+v", js)
	if js.Zeek < 1000 || js.Matched != js.Zeek || js.Ambiguous != 0 || js.UnmatchedC2P != 0 || js.PosMatched != js.Positives || js.Positives == 0 {
		t.Fatalf("clean join not 100 %%: %+v", js)
	}
	c2 := 0
	for _, s := range clean.Series {
		if s.Label == "c2" {
			c2++
			if !strings.HasPrefix(s.Cell, "synth:") {
				t.Errorf("cell metadata from the label file missing: %q", s.Cell)
			}
		}
	}
	if c2 == 0 {
		t.Fatal("no series labelled c2 through the UID join")
	}

	// damage the pcaps only
	dmg := filepath.Join(dir, "damaged")
	_ = os.MkdirAll(dmg, 0o755)
	for i, me := range rows {
		pk, err := perturb.Read(filepath.Join(dir, me.Path))
		if err != nil {
			t.Fatal(err)
		}
		pk, _ = perturb.Drop(pk, 0.01, uint64(100+i))
		pk, _ = perturb.Jitter(pk, 0.5, uint64(200+i))
		if err := perturb.Write(filepath.Join(dmg, me.Path), pk); err != nil {
			t.Fatal(err)
		}
	}
	dm := joinManifest(t, dir, dmg, rows)
	js = joinTotals(run(dm))
	t.Logf("drop 0.01 + jitter 0.5: %+v", js)
	if js.Rate < 0.99 {
		t.Errorf("damaged join %.4f < 0.99: %+v", js.Rate, js)
	}

	joinTolerance = 0.01 // µs-exact starts still match; 0.5 s jitter does not
	defer func() { joinTolerance = 1 }()
	js = joinTotals(run(dm))
	t.Logf("mutation (tolerance 10 ms): %+v", js)
	if js.Rate >= 0.99 {
		t.Errorf("mutation: join still %.4f with no start tolerance", js.Rate)
	}
}

// The readers accept TSV, JSON lines and CSV, plain or gzipped, with
// custom column names; bad rows are counted, not fatal.
func TestZeekReaders(t *testing.T) {
	tsv := "#separator \\x09\n#unset_field\t-\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\tlabel\n" +
		"1711368055.5\tCa\t10.0.0.1\t5000\t192.0.2.1\t443\ttcp\t1.5\tc2\n" +
		"1711368056.5\tCb\t10.0.0.1\t5001\t192.0.2.1\t53\tudp\t-\tbenign\n" +
		"1711368057.5\tCc\tnot-an-ip\t5001\t192.0.2.1\t53\tudp\t-\tbenign\n"
	json := `{"ts":"2024-03-25T12:00:55.5Z","uid":"Ca","id.orig_h":"10.0.0.1","id.orig_p":5000,"id.resp_h":"192.0.2.1","id.resp_p":443,"proto":"tcp","label":"c2"}` + "\n" +
		`{"ts":1711368056.5,"uid":"Cb","id.orig_h":"10.0.0.1","id.orig_p":5001,"id.resp_h":"192.0.2.1","id.resp_p":53,"proto":"udp","label":null}` + "\n"
	csvs := "start,flow,src,sport,dst,dport,p,y\n1711368055.5,Ca,10.0.0.1,5000,192.0.2.1,443,TCP,malicious\n"
	gz := func(s string) string {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		w.Write([]byte(s))
		w.Close()
		return b.String()
	}
	custom := Columns{TS: "start", UID: "flow", OrigH: "src", OrigP: "sport", RespH: "dst", RespP: "dport", Proto: "p", Label: "y"}
	for _, c := range []struct {
		name string
		data string
		cols Columns
		n    int
		bad  int
	}{
		{"tsv", tsv, Columns{}, 2, 1}, {"tsv.gz", gz(tsv), Columns{}, 2, 1}, {"json", json, Columns{}, 2, 0}, {"json.gz", gz(json), Columns{}, 2, 0},
		{"csv-custom", csvs, custom, 1, 0},
	} {
		p := filepath.Join(t.TempDir(), "conn.log")
		_ = os.WriteFile(p, []byte(c.data), 0o644)
		zs, bad, err := ReadConnLog(p, c.cols.withDefaults(nil))
		if err != nil || len(zs) != c.n || bad != c.bad {
			t.Errorf("%s: %d conns, %d bad, err %v", c.name, len(zs), bad, err)
			continue
		}
		z := zs[0]
		if z.UID != "Ca" || z.TS != 1711368055.5 || z.OrigP != 5000 || z.RespP != 443 || z.Proto != "tcp" || z.OrigH.String() != "10.0.0.1" {
			t.Errorf("%s: row %+v", c.name, z)
		}
		if !positiveSet(nil)[strings.ToLower(z.Label)] {
			t.Errorf("%s: label %q not positive", c.name, z.Label)
		}
	}
}

// Join edge cases: reversed direction matches; two c2parser connections
// in the tolerance window are ambiguous; two Zeek rows claiming one
// connection are ambiguous.
func TestZeekJoinEdges(t *testing.T) {
	cs := []engine.ConnRecord{
		{Proto: "tcp", Client: "10.0.0.1", ClientPort: 5000, Server: "192.0.2.1", ServerPort: 443, Start: 100},
		{Proto: "tcp", Client: "10.0.0.2", ClientPort: 6000, Server: "192.0.2.1", ServerPort: 443, Start: 200},
		{Proto: "tcp", Client: "10.0.0.2", ClientPort: 6000, Server: "192.0.2.1", ServerPort: 443, Start: 200.5},
		{Proto: "udp", Client: "10.0.0.3", ClientPort: 7000, Server: "192.0.2.53", ServerPort: 53, Start: 300},
		{Proto: "tcp", Client: "10.0.0.9", ClientPort: 9, Server: "192.0.2.9", ServerPort: 9, Start: 900},
	}
	zc := func(uid, a string, ap uint16, b string, bp uint16, proto string, ts float64) ZeekConn {
		z, err := ParseConn(Record{"uid": uid, "ts": fmt.Sprint(ts), "id.orig_h": a, "id.orig_p": fmt.Sprint(ap), "id.resp_h": b,
			"id.resp_p": fmt.Sprint(bp), "proto": proto}, (*Columns)(nil).withDefaults(nil))
		if err != nil {
			t.Fatal(err)
		}
		return z
	}
	zs := []ZeekConn{
		zc("C1", "192.0.2.1", 443, "10.0.0.1", 5000, "tcp", 100.4), // reversed
		zc("C2", "10.0.0.2", 6000, "192.0.2.1", 443, "tcp", 200.2), // two candidates
		zc("C3", "10.0.0.3", 7000, "192.0.2.53", 53, "udp", 300.9),
		zc("C4", "10.0.0.3", 7000, "192.0.2.53", 53, "udp", 299.5), // claims the same record as C3
		zc("C5", "10.0.0.4", 1, "192.0.2.4", 1, "tcp", 100),        // nothing
		zc("C6", "10.0.0.1", 5000, "192.0.2.1", 443, "tcp", 102.0), // outside ±1 s
	}
	st, m := Join(zs, cs)
	if st.Matched != 1 || m["C1"] != 0 || st.Ambiguous != 3 || st.UnmatchedZeek != 2 || st.UnmatchedC2P != 4 {
		t.Errorf("join %+v matched %v", st, m)
	}
}

func FuzzZeekRecords(f *testing.F) {
	f.Add([]byte("#separator \\x09\n#fields\tts\tuid\tid.orig_h\n1.0\tC\t10.0.0.1\n"))
	f.Add([]byte(`{"ts":1,"uid":"C","id.orig_h":"::1","x":{"y":[1,2]}}` + "\n"))
	f.Add([]byte("a,b\n1,\"2\n"))
	f.Add([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, d []byte) {
		cols := (*Columns)(nil).withDefaults(nil)
		_ = ReadRecords(bytes.NewReader(d), func(r Record) error {
			ParseConn(r, cols)
			return nil
		})
	})
}

func FuzzManifest(f *testing.F) {
	f.Add([]byte("version: 2\ncaptures:\n  - path: a/*.pcap\n    role: mixed\n    labels: {source: zeek-uid, conn_log: x.log}\n"))
	f.Add([]byte("captures:\n  - path: x.pcap\n    benign: true\n"))
	f.Add([]byte("version: 2\ncaptures:\n  - path: x\n    role: c2\n    labels: {source: time-window, windows: [{start: '2024-01-01T00:00:00Z', end: '1704070000'}]}\n"))
	f.Fuzz(func(t *testing.T, d []byte) {
		m, err := ParseManifest(d)
		if err == nil && len(m.Captures) == 0 {
			t.Fatal("accepted a manifest with no captures")
		}
	})
}
