package synth

import (
	"bytes"
	"io"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"c2parser/internal/pcapio"
)

func scenarios(t *testing.T) []*Scenario {
	t.Helper()
	files, _ := filepath.Glob("../../corpus/scenarios/*.yaml")
	if len(files) == 0 {
		t.Fatal("no scenarios")
	}
	sort.Strings(files)
	var out []*Scenario
	for _, f := range files {
		sc, err := LoadScenario(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out = append(out, sc)
	}
	return out
}

// Phase 1.4 determinism gate: the same (scenario, seed) yields a
// byte-identical capture; a different seed yields a different one.
func TestDeterminism(t *testing.T) {
	for _, sc := range scenarios(t) {
		var a, b, c bytes.Buffer
		if _, err := Generate(sc, &a); err != nil {
			t.Fatalf("%s: %v", sc.Name, err)
		}
		if _, err := Generate(sc, &b); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a.Bytes(), b.Bytes()) {
			t.Errorf("%s: two runs differ", sc.Name)
		}
		sc2 := *sc
		sc2.Seed++
		if _, err := Generate(&sc2, &c); err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(a.Bytes(), c.Bytes()) && !fixedOnly(sc) {
			t.Errorf("%s: seed has no effect", sc.Name)
		}
	}
}

// fixedOnly: every stream is fully determined without randomness that the
// seed reaches (none in the shipped corpus; kept for future scenarios).
func fixedOnly(sc *Scenario) bool { return false }

// Every packet reads back in time order with orig_len ≥ stored length, in
// pcap and pcapng; snaplen truncates but keeps the wire length.
func TestReadBack(t *testing.T) {
	for _, sc := range scenarios(t) {
		dir := t.TempDir()
		me, err := WriteFile(sc, dir)
		if err != nil {
			t.Fatal(err)
		}
		r, err := pcapio.Open(filepath.Join(dir, me.Path))
		if err != nil {
			t.Fatalf("%s: %v", sc.Name, err)
		}
		var last time.Time
		n, trunc := 0, 0
		for {
			p, err := r.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("%s: %v", sc.Name, err)
			}
			if p.Timestamp.Before(last) {
				t.Fatalf("%s: packet %d out of order", sc.Name, n)
			}
			last = p.Timestamp
			if p.OrigLen < len(p.Data) {
				t.Fatalf("%s: orig_len %d < caplen %d", sc.Name, p.OrigLen, len(p.Data))
			}
			if p.OrigLen > len(p.Data) {
				trunc++
				if sc.Snaplen == 0 || len(p.Data) != sc.Snaplen {
					t.Fatalf("%s: truncated to %d without snaplen %d", sc.Name, len(p.Data), sc.Snaplen)
				}
			}
			n++
		}
		r.Close()
		if n == 0 {
			t.Errorf("%s: empty capture", sc.Name)
		}
		if sc.Snaplen > 0 && trunc == 0 {
			t.Errorf("%s: snaplen %d truncated nothing", sc.Name, sc.Snaplen)
		}
		if len(me.C2) == 0 != me.Benign {
			t.Errorf("%s: benign=%v but %d c2 labels", sc.Name, me.Benign, len(me.C2))
		}
	}
}

func TestScenarioValidation(t *testing.T) {
	base := `name: x
seed: 1
streams:
  - label: c2
    transport: https-keepalive
    server: 198.51.100.1
    topology: {clients: [10.0.0.1]}
    timing: {model: shortening, sleep: 60, jitter: 0.1, events: 10}
`
	if _, err := ParseScenario([]byte(base)); err != nil {
		t.Fatalf("valid scenario rejected: %v", err)
	}
	bad := map[string]string{
		"unknown key":     strings.Replace(base, "seed: 1", "seed: 1\nsleeep: 3", 1),
		"framework name":  strings.Replace(base, "name: x", "name: sliver-https", 1),
		"framework shape": strings.Replace(base, "label: c2", "label: c2\n    shape: cobaltstrike-like", 1),
		"bad transport":   strings.Replace(base, "https-keepalive", "carrier-pigeon", 1),
		"bad model":       strings.Replace(base, "shortening", "chaotic", 1),
		"no events":       strings.Replace(base, "events: 10", "events: 0", 1),
		"bad jitter":      strings.Replace(base, "jitter: 0.1", "jitter: 1.5", 1),
		"bad label":       strings.Replace(base, "label: c2", "label: maybe", 1),
		"no clients":      strings.Replace(base, "clients: [10.0.0.1]", "clients: []", 1),
		"bad encoding":    strings.Replace(base, "events: 10}", "events: 10}\n    content: {encoding: rot13}", 1),
	}
	for name, y := range bad {
		if _, err := ParseScenario([]byte(y)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Jitter polarity: shortening gaps lie in [S(1−J), S], lengthening in
// [S, S(1+J)], symmetric in [S(1−J), S(1+J)]; anchored events sit within
// J·S after a grid point; lattice gaps are whole seconds.
func TestTimingModels(t *testing.T) {
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	gaps := func(m Timing) []float64 {
		ev := Schedule(start, m, Artifacts{}, rand.New(rand.NewPCG(1, 2)))
		var g []float64
		prev := start
		for _, e := range ev {
			g = append(g, e.At.Sub(prev).Seconds())
			prev = e.At
		}
		return g
	}
	const S, J, eps = 60.0, 0.2, 1e-6
	for _, c := range []struct {
		model  string
		lo, hi float64
	}{{"shortening", S * (1 - J), S}, {"lengthening", S, S * (1 + J)}, {"symmetric", S * (1 - J), S * (1 + J)}, {"fixed", S, S}} {
		g := gaps(Timing{Model: c.model, Sleep: S, Jitter: J, Events: 500})
		if len(g) != 500 {
			t.Fatalf("%s: %d events", c.model, len(g))
		}
		for _, x := range g {
			if x < c.lo-eps || x > c.hi+eps {
				t.Fatalf("%s: gap %.3f outside [%.1f, %.1f]", c.model, x, c.lo, c.hi)
			}
		}
	}
	for _, x := range gaps(Timing{Model: "lattice", Sleep: 30, Jitter: 0.2, Events: 200}) {
		if x != math.Round(x) {
			t.Fatalf("lattice gap %.3f not whole", x)
		}
	}
	ev := Schedule(start, Timing{Model: "anchored", Sleep: S, Jitter: J, Events: 200}, Artifacts{}, rand.New(rand.NewPCG(3, 4)))
	for _, e := range ev {
		off := math.Mod(e.At.Sub(start).Seconds(), S)
		if off > J*S+eps {
			t.Fatalf("anchored offset %.2f > %.2f", off, J*S)
		}
	}
	g := gaps(Timing{Model: "backoff", Sleep: 10, Factor: 2, Max: 80, Events: 8})
	want := []float64{10, 20, 40, 80, 10, 20, 40, 80}
	for i := range want {
		if math.Abs(g[i]-want[i]) > eps {
			t.Fatalf("backoff gaps %v, want %v", g, want)
		}
	}
	// gamma(k) mean ≈ Sleep
	var sum float64
	gg := gaps(Timing{Model: "gamma", Shape: 0.5, Sleep: 100, Events: 20000})
	for _, x := range gg {
		sum += x
	}
	if m := sum / float64(len(gg)); math.Abs(m-100) > 5 {
		t.Errorf("gamma(0.5) mean %.1f, want ≈ 100", m)
	}
	// scheduler models land in their documented ranges
	for _, c := range []struct {
		model  string
		lo, hi float64
	}{{"jamf", 600, 1200}, {"gpo", 5400, 7200}, {"wsus", 63360, 79200}, {"chrony", 1024, 1044.48}, {"wireguard", 24.99, 25.01}} {
		for _, x := range gaps(Timing{Model: c.model, Events: 300}) {
			if x < c.lo-eps || x > c.hi+eps {
				t.Fatalf("%s gap %.3f outside [%.2f, %.2f]", c.model, x, c.lo, c.hi)
			}
		}
	}
}

func TestArtifacts(t *testing.T) {
	start := time.Date(2024, 1, 1, 6, 0, 0, 0, time.UTC)
	m := Timing{Model: "fixed", Sleep: 60, Events: 100}
	r := func() *rand.Rand { return rand.New(rand.NewPCG(5, 6)) }
	// missed beats leave harmonic gaps
	ev := Schedule(start, m, Artifacts{Missed: 0.2}, r())
	harm := 0
	for i := 1; i < len(ev); i++ {
		if g := ev[i].At.Sub(ev[i-1].At).Seconds(); g >= 119 {
			harm++
		}
	}
	if len(ev) != 100 || harm == 0 {
		t.Errorf("missed: %d events, %d harmonic gaps", len(ev), harm)
	}
	// tasking bursts
	ev = Schedule(start, m, Artifacts{Tasking: &Tasking{Every: 10, Burst: 3, Gap: 2}}, r())
	tk := 0
	for _, e := range ev {
		if e.Tasking {
			tk++
		}
	}
	if tk == 0 || tk%3 != 0 {
		t.Errorf("tasking: %d follow-ups", tk)
	}
	// sleep change
	ev = Schedule(start, m, Artifacts{SleepChange: &SleepChange{After: 50, Sleep: 120}}, r())
	if g := ev[len(ev)-1].At.Sub(ev[len(ev)-2].At).Seconds(); g != 120 {
		t.Errorf("sleep change: last gap %.0f", g)
	}
	// stall
	ev = Schedule(start, m, Artifacts{Stalls: []Stall{{After: 10, Seconds: 600}}}, r())
	if g := ev[10].At.Sub(ev[9].At).Seconds(); g != 660 {
		t.Errorf("stall: gap %.0f, want 660", g)
	}
	// working hours
	ev = Schedule(start, Timing{Model: "fixed", Sleep: 3600, Events: 48}, Artifacts{WorkingHours: &Hours{Start: 8, End: 18}}, r())
	for _, e := range ev {
		if h := e.At.UTC().Hour(); h < 8 || h >= 18 {
			t.Fatalf("working hours: event at %s", e.At)
		}
	}
	// second implant on the same key
	ev = Schedule(start, m, Artifacts{Second: &Timing{Model: "fixed", Sleep: 300, Events: 10}}, r())
	if len(ev) != 110 || !sort.SliceIsSorted(ev, func(i, j int) bool { return ev[i].At.Before(ev[j].At) }) {
		t.Errorf("second implant: %d events (want 110, sorted)", len(ev))
	}
}

// Content shapes: residue class of the decoded length and header bytes.
func TestContentShapes(t *testing.T) {
	r := rand.New(rand.NewPCG(9, 9))
	for _, res := range []string{"0", "4", "12"} {
		k, err := newKeyed(Content{Header: "c0ffee01", Residue: res, Pad: [2]int{0, 32}}, r)
		if err != nil {
			t.Fatal(err)
		}
		for n := 1; n < 200; n += 7 {
			d := k.decoded(r, n)
			if got := len(d) % 16; res != "" && got != map[string]int{"0": 0, "4": 4, "12": 12}[res] {
				t.Fatalf("residue %s: len %d ≡ %d", res, len(d), got)
			}
			if !bytes.HasPrefix(d, []byte{0xc0, 0xff, 0xee, 0x01}) {
				t.Fatal("header missing")
			}
		}
	}
	k, _ := newKeyed(Content{XORKey: 8}, r)
	d := k.decoded(r, 400)
	const plain = "status=ok;id=0042;q=queue;cmd=none;data="
	for i := 0; i+8 < len(d); i++ { // the key cancels at lag 8
		if d[i]^d[i+8] != plain[i%len(plain)]^plain[(i+8)%len(plain)] {
			t.Fatalf("xor: lag-8 structure broken at %d", i)
		}
	}
	if len(k.key) != 8 {
		t.Errorf("xor key length %d", len(k.key))
	}
	for _, enc := range []string{"base64", "base64url", "base32", "base58", "words", "hex", "netbios", "text"} {
		k, _ := newKeyed(Content{Encoding: enc}, r)
		b := k.body(r, 64)
		for _, c := range b {
			if c < 0x20 || c > 0x7e {
				if !(enc == "text" && c == '\n') {
					t.Fatalf("%s: non-printable byte %#x", enc, c)
				}
			}
		}
	}
	if f := Frame("le32", []byte("abc")); !bytes.Equal(f[:4], []byte{3, 0, 0, 0}) {
		t.Errorf("le32 %x", f[:4])
	}
	if f := Frame("be12", []byte("abc")); len(f) != 15 || f[3] != 3 {
		t.Errorf("be12 %x", f)
	}
}

// v11a encoders: base58 against a published vector, round trips, word
// letter sums, the constant wrapper.
func TestV11aEncoders(t *testing.T) {
	if got := Base58([]byte("Hello World!")); got != "2NEpo7TZRRrLZSi2U" {
		t.Errorf("base58 vector: %s", got)
	}
	if got := Base58([]byte{0, 0, 1}); got != "112" {
		t.Errorf("base58 leading zeros: %s", got)
	}
	r := rand.New(rand.NewPCG(5, 5))
	b := RandBytes(r, 300)
	ws := strings.Fields(Words(b))
	if len(ws) != len(b) {
		t.Fatalf("words: %d for %d bytes", len(ws), len(b))
	}
	for i, w := range ws {
		if byte(letterSum(w)) != b[i] {
			t.Fatalf("word %d %q sums to %d, want %d", i, w, byte(letterSum(w)), b[i])
		}
	}
	if Words(b) != Words(b) {
		t.Error("words not deterministic")
	}
	k, err := newKeyed(Content{Encoding: "base32", Wrap: [2]string{"SESSIONID=", ";"}}, r)
	if err != nil {
		t.Fatal(err)
	}
	if body := string(k.body(r, 40)); !strings.HasPrefix(body, "SESSIONID=") || !strings.HasSuffix(body, ";") {
		t.Errorf("wrap: %q", body)
	}
	if _, err := newKeyed(Content{Encoding: "base99"}, r); err == nil {
		t.Error("unknown encoding accepted")
	}
}

// The committed corpus stays small: scenario files only, each < 200 KB.
func TestCorpusRules(t *testing.T) {
	err := filepath.Walk("../../corpus", func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".md") {
			t.Errorf("%s: only scenario YAML and docs are committed under corpus/", p)
		}
		if fi.Size() > 200<<10 {
			t.Errorf("%s: %d bytes > 200 KB", p, fi.Size())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
