package perturb_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"c2parser/internal/engine"
	. "c2parser/internal/perturb"
	"c2parser/internal/synth"
)

// scenario generates a corpus scenario into memory.
func scenario(t *testing.T, name string) []Packet {
	t.Helper()
	sc, err := synth.LoadScenario("../../corpus/scenarios/" + name + ".yaml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	me, err := synth.WriteFile(sc, dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Read(filepath.Join(dir, me.Path))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func analyze(t *testing.T, pkts []Packet, cfg engine.Config) *engine.Result {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.pcap")
	if err := Write(p, pkts); err != nil {
		t.Fatal(err)
	}
	res, err := engine.AnalyzeFile(p, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func pcapBytes(t *testing.T, pkts []Packet) []byte {
	var b bytes.Buffer
	if err := WriteTo(&b, pkts); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// scores is the sorted multiset of (category, score) — address-free.
func scores(res *engine.Result) []string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, fmt.Sprintf("%s %.4f", f.Category, f.Score))
	}
	sort.Strings(out)
	return out
}

func titles(res *engine.Result) []string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, fmt.Sprintf("%.4f %s", f.Score, f.Title))
	}
	sort.Strings(out)
	return out
}

var cfgs = []engine.Config{{}, {TimingV2: true}}

func eng(c engine.Config) string { return map[bool]string{false: "v1", true: "v2"}[c.TimingV2] }

// corpus is the set of scenarios the transform gates run on.
var corpus = []string{"gate-single-https-keepalive-60s", "gate-single-https-new-conn-30s", "shape-artifacts-http",
	"shape-smb-pipe-framed", "shape-dns-txt-base32", "shape-websocket-poll"}

// Phase 1.4: damage at 0 % is a byte-level no-op.
func TestDamageZeroIsNoop(t *testing.T) {
	for _, name := range corpus {
		in := scenario(t, name)
		want := pcapBytes(t, in)
		for tname, f := range map[string]func([]Packet) []Packet{
			"drop":     func(p []Packet) []Packet { o, _ := Drop(p, 0, 1); return o },
			"dup":      func(p []Packet) []Packet { o, _ := Dup(p, 0, 1); return o },
			"reorder":  func(p []Packet) []Packet { o, _ := Reorder(p, 0, 1); return o },
			"jitter":   func(p []Packet) []Packet { o, _ := Jitter(p, 0, 1); return o },
			"conflict": func(p []Packet) []Packet { o, _ := Conflict(p, 0, true, 1); return o },
			"snap0":    func(p []Packet) []Packet { o, _ := Snap(p, 0); return o },
			"skip0":    func(p []Packet) []Packet { o, _ := Skip(p, 0); return o },
			"identity-readdress": func(p []Packet) []Packet {
				o, _, err := Readdress(p, AddrMap{})
				if err != nil {
					t.Fatal(err)
				}
				return o
			},
		} {
			if got := pcapBytes(t, f(in)); !bytes.Equal(got, want) {
				t.Errorf("%s %s at 0 %% changed the capture", name, tname)
			}
		}
	}
}

// remapAll maps every IPv4 address to a fresh one of the same class
// (internal stays internal), deterministically.
func remapAll(pkts []Packet) AddrMap {
	seen := map[netip.Addr]bool{}
	for _, p := range pkts {
		d := p.Data
		if len(d) < 34 || binary.BigEndian.Uint16(d[12:]) != 0x0800 {
			continue
		}
		seen[netip.AddrFrom4([4]byte(d[26:30]))] = true
		seen[netip.AddrFrom4([4]byte(d[30:34]))] = true
	}
	var as []netip.Addr
	for a := range seen {
		as = append(as, a)
	}
	sort.Slice(as, func(i, j int) bool { return as[i].Less(as[j]) })
	m := AddrMap{IP: map[netip.Addr]netip.Addr{}}
	for i, a := range as {
		if a.IsPrivate() {
			m.IP[a] = netip.AddrFrom4([4]byte{172, 20, byte(i >> 8), byte(i)})
		} else {
			m.IP[a] = netip.AddrFrom4([4]byte{45, 33, byte(i >> 8), byte(i)})
		}
	}
	return m
}

// Phase 1.4: re-addressing is a metamorphic no-op on scores.
func TestReaddressMetamorphic(t *testing.T) {
	for _, name := range corpus {
		in := scenario(t, name)
		m := remapAll(in)
		out, ch, err := Readdress(in, m)
		if err != nil {
			t.Fatal(err)
		}
		if ch.Changed == 0 {
			t.Fatalf("%s: nothing rewritten", name)
		}
		for _, cfg := range cfgs {
			a, b := scores(analyze(t, in, cfg)), scores(analyze(t, out, cfg))
			if strings.Join(a, "\n") != strings.Join(b, "\n") {
				t.Errorf("%s %s: re-addressing changed scores\n before %v\n after  %v", name, eng(cfg), a, b)
			}
		}
		// mapping back restores the original bytes
		inv := AddrMap{IP: map[netip.Addr]netip.Addr{}}
		for a, b := range m.IP {
			inv.IP[b] = a
		}
		back, _, _ := Readdress(out, inv)
		if !bytes.Equal(pcapBytes(t, back), pcapBytes(t, in)) {
			t.Errorf("%s: readdress round trip is not byte-identical (checksums?)", name)
		}
	}
}

// Incremental checksum updates match a from-scratch computation.
func TestChecksums(t *testing.T) {
	in := scenario(t, "shape-artifacts-http")
	out, _, _ := Readdress(in, AddrMap{IP: map[netip.Addr]netip.Addr{
		netip.MustParseAddr("10.5.0.29"): netip.MustParseAddr("10.99.1.2")}, Port: map[uint16]uint16{80: 8080}})
	bad := 0
	for _, p := range out {
		if !checksumsOK(p.Data) {
			bad++
		}
	}
	if bad > 0 {
		t.Errorf("%d packets with bad checksums after rewrite", bad)
	}
}

func sum16(b []byte, s uint32) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	return s
}

func fold(s uint32) uint16 {
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return uint16(s)
}

func checksumsOK(d []byte) bool {
	if len(d) < 34 || binary.BigEndian.Uint16(d[12:]) != 0x0800 {
		return true
	}
	ip := d[14:]
	ihl := int(ip[0]&0x0f) * 4
	if fold(sum16(ip[:ihl], 0)) != 0xffff {
		return false
	}
	total := int(binary.BigEndian.Uint16(ip[2:]))
	if ip[9] != 6 && ip[9] != 17 || len(ip) < total {
		return true
	}
	seg := ip[ihl:total]
	if ip[9] == 17 && binary.BigEndian.Uint16(seg[6:]) == 0 {
		return true
	}
	s := sum16(ip[12:20], uint32(ip[9])+uint32(len(seg)))
	return fold(sum16(seg, s)) == 0xffff
}

// channelOf returns the strongest C2 finding's TCP channel.
func channelOf(t *testing.T, res *engine.Result) Channel {
	t.Helper()
	for _, f := range res.Findings {
		if f.Category != engine.CatC2 || f.Client == "" {
			continue
		}
		hp, _, _ := strings.Cut(f.Server, "/")
		if ap, err := netip.ParseAddrPort(hp); err == nil {
			return Channel{Client: netip.MustParseAddr(f.Client), Server: ap.Addr(), Port: ap.Port()}
		}
		if a, err := netip.ParseAddr(hp); err == nil {
			return Channel{Client: netip.MustParseAddr(f.Client), Server: a}
		}
	}
	t.Fatal("no C2 channel finding")
	return Channel{}
}

// Phase 1.4: re-timing a channel to its original schedule reproduces the
// original findings exactly; re-timing to a model moves only times
// (realism: per-transaction request/response bytes identical).
func TestRetime(t *testing.T) {
	for _, name := range []string{"gate-single-https-keepalive-60s", "gate-single-https-new-conn-30s", "shape-artifacts-http", "shape-websocket-poll"} {
		in := scenario(t, name)
		ch := channelOf(t, analyze(t, in, engine.Config{}))
		txns := Transactions(in, ch)
		if len(txns) < 10 {
			t.Fatalf("%s: %d transactions", name, len(txns))
		}
		starts := make([]time.Time, len(txns))
		for i, x := range txns {
			starts[i] = x.Start
		}
		same, _, err := RetimeTo(in, ch, starts)
		if err != nil {
			t.Fatal(err)
		}
		for _, cfg := range cfgs {
			if a, b := titles(analyze(t, in, cfg)), titles(analyze(t, same, cfg)); strings.Join(a, "\n") != strings.Join(b, "\n") {
				t.Errorf("%s %s: re-time to original changed findings\n %v\n %v", name, eng(cfg), a, b)
			}
		}
		out, c, err := Retime(in, ch, synth.Timing{Model: "lengthening", Sleep: 45, Jitter: 0.3}, synth.Artifacts{}, 9)
		if err != nil {
			t.Fatal(err)
		}
		after := Transactions(out, ch)
		if len(after) != len(txns) || len(out) != len(in) {
			t.Fatalf("%s: %d→%d transactions, %d→%d packets (%s)", name, len(txns), len(after), len(in), len(out), c.Detail)
		}
		for i := range txns {
			if txns[i].ReqBytes != after[i].ReqBytes || txns[i].RespBytes != after[i].RespBytes || len(txns[i].Packets) != len(after[i].Packets) {
				t.Fatalf("%s txn %d: bytes %d/%d → %d/%d", name, i, txns[i].ReqBytes, txns[i].RespBytes, after[i].ReqBytes, after[i].RespBytes)
			}
		}
		if !samePayloads(in, out) {
			t.Errorf("%s: re-time changed packet bytes", name)
		}
		// the new cadence is the model's: median gap within the model range
		var gaps []float64
		for i := 1; i < len(after); i++ {
			gaps = append(gaps, after[i].Start.Sub(after[i-1].Start).Seconds())
		}
		sort.Float64s(gaps)
		if med := gaps[len(gaps)/2]; med < 45 || med > 45*1.3+1 {
			t.Errorf("%s: re-timed median gap %.1fs, want in [45, 58.5] (%s)", name, med, c.Detail)
		}
	}
}

// samePayloads: the multiset of packet bytes is unchanged.
func samePayloads(a, b []Packet) bool {
	if len(a) != len(b) {
		return false
	}
	h := map[string]int{}
	for _, p := range a {
		h[string(p.Data)]++
	}
	for _, p := range b {
		h[string(p.Data)]--
	}
	for _, v := range h {
		if v != 0 {
			return false
		}
	}
	return true
}

// Phase 1.2 → 0.1: a single-host beacon cloned onto 3 clients becomes a
// fleet pattern and is capped below medium; the original alone is not.
func TestCloneMakesFleet(t *testing.T) {
	in := scenario(t, "gate-single-https-keepalive-60s")
	out, _, err := Clone(in, netip.MustParseAddr("10.5.0.16"),
		[]netip.Addr{netip.MustParseAddr("10.5.0.17"), netip.MustParseAddr("10.5.0.18")}, 7*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range cfgs {
		res := analyze(t, out, cfg)
		n := 0
		for _, f := range res.Findings {
			if f.Category == engine.CatC2 && strings.Contains(f.Title, "198.51.100.41") {
				n++
				if f.Score > engine.TimingOnlyCap {
					t.Errorf("%s: cloned fleet member %s scores %.2f", eng(cfg), f.Client, f.Score)
				}
			}
		}
		if n != 3 {
			t.Errorf("%s: %d fleet findings, want 3", eng(cfg), n)
		}
	}
}

// Redirect spreads flows over k IPs; every flow keeps one address.
func TestRedirect(t *testing.T) {
	in := scenario(t, "gate-single-https-new-conn-30s")
	to := []netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2"), netip.MustParseAddr("203.0.113.3")}
	out, ch, err := Redirect(in, netip.MustParseAddr("198.51.100.41"), to, "round-robin", 1)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Params["flows"].(int) < 60 {
		t.Errorf("flows %v", ch.Params["flows"])
	}
	res := analyze(t, out, engine.Config{TimingV2: true})
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "198.51.100.41") {
			t.Errorf("original server still present: %s", f.Title)
		}
	}
	for _, p := range out {
		if !checksumsOK(p.Data) {
			t.Fatal("bad checksum after redirect")
		}
	}
}

// Splicing benign background into a C2 capture never lowers the C2 score
// (Phase 4 metamorphic invariant, exercised here on the corpus).
func TestSpliceNeverLowersC2(t *testing.T) {
	bg := scenario(t, "benign-models")
	for _, name := range []string{"gate-single-https-keepalive-60s", "shape-artifacts-http", "shape-smb-pipe-framed", "shape-dns-txt-base32"} {
		c2 := scenario(t, name)
		mix, _, err := Splice(bg, c2, 2*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		for _, cfg := range cfgs {
			before, after := analyze(t, c2, cfg), analyze(t, mix, cfg)
			top := before.Findings[0]
			var got *engine.Finding
			for i := range after.Findings {
				f := &after.Findings[i]
				if f.Title == top.Title {
					got = f
				}
			}
			if got == nil || got.Score < top.Score-1e-9 {
				t.Errorf("%s %s: spliced into background, %q %.2f → %v", name, eng(cfg), top.Title, top.Score, got)
			}
		}
	}
}

// Encapsulation (VLAN, QinQ, GRE, ERSPAN II, VXLAN) is transparent: the
// same findings with the same scores.
func TestWrapTransparent(t *testing.T) {
	for _, name := range []string{"gate-single-https-keepalive-60s", "shape-artifacts-http", "shape-dns-txt-base32", "shape-smb-pipe-framed"} {
		in := scenario(t, name)
		for _, kind := range []string{"vlan", "qinq", "gre", "erspan", "vxlan"} {
			out, _, err := Wrap(in, kind)
			if err != nil {
				t.Fatal(err)
			}
			for _, cfg := range cfgs {
				a, b := titles(analyze(t, in, cfg)), titles(analyze(t, out, cfg))
				if strings.Join(a, "\n") != strings.Join(b, "\n") {
					t.Errorf("%s %s %s: encapsulation changed findings\n plain %v\n wrapped %v", name, kind, eng(cfg), a, b)
				}
			}
		}
	}
}

// One-direction capture keeps exactly one side of every flow.
func TestOneWay(t *testing.T) {
	in := scenario(t, "shape-artifacts-http")
	c2s, _, _ := OneWay(in, "c2s")
	s2c, _, _ := OneWay(in, "s2c")
	if len(c2s)+len(s2c) != len(in) || len(c2s) == 0 || len(s2c) == 0 {
		t.Fatalf("split %d + %d of %d", len(c2s), len(s2c), len(in))
	}
	for _, p := range c2s {
		if len(p.Data) >= 34 && netip.AddrFrom4([4]byte(p.Data[26:30])) != netip.MustParseAddr("10.5.0.29") {
			t.Fatal("c2s kept a server packet")
		}
	}
	for _, cfg := range cfgs { // must not crash; record what survives
		t.Logf("%s c2s: %v", eng(cfg), titles(analyze(t, c2s, cfg)))
		t.Logf("%s s2c: %v", eng(cfg), titles(analyze(t, s2c, cfg)))
	}
}

// Conflicting retransmissions: the C2 finding survives 2 % conflicts in
// either order (first-wins or last-wins).
func TestConflictingRetransmissions(t *testing.T) {
	in := scenario(t, "shape-artifacts-http")
	base := analyze(t, in, engine.Config{}).Findings[0]
	for _, before := range []bool{false, true} {
		out, ch := Conflict(in, 0.02, before, 3)
		if ch.Changed == 0 {
			t.Fatal("no conflicts inserted")
		}
		for _, cfg := range cfgs {
			res := analyze(t, out, cfg)
			if len(res.Findings) == 0 || res.Findings[0].Title != base.Title || math.Abs(res.Findings[0].Score-base.Score) > 0.25 {
				t.Errorf("before=%v %s: top finding %v (clean %.2f %s)", before, eng(cfg), titles(res), base.Score, base.Title)
			}
		}
	}
}

// Determinism of the random transforms.
func TestTransformsDeterministic(t *testing.T) {
	in := scenario(t, "shape-artifacts-http")
	for name, f := range map[string]func() []Packet{
		"drop":     func() []Packet { o, _ := Drop(in, 0.05, 7); return o },
		"dup":      func() []Packet { o, _ := Dup(in, 0.05, 7); return o },
		"reorder":  func() []Packet { o, _ := Reorder(in, 0.05, 7); return o },
		"jitter":   func() []Packet { o, _ := Jitter(in, 0.5, 7); return o },
		"conflict": func() []Packet { o, _ := Conflict(in, 0.05, true, 7); return o },
	} {
		if !bytes.Equal(pcapBytes(t, f()), pcapBytes(t, f())) {
			t.Errorf("%s not deterministic", name)
		}
	}
}

// labCapture returns a lab capture path or skips.
func labCapture(t *testing.T, contains string) string {
	dir := os.Getenv("C2PARSER_TESTDATA")
	if dir == "" {
		t.Skip("C2PARSER_TESTDATA not set")
	}
	m, _ := filepath.Glob(filepath.Join(dir, "*.pcap*"))
	for _, p := range m {
		b := filepath.Base(p)
		if strings.Contains(b, contains) && !(contains == "http_c2_enum" && strings.Contains(b, "part2")) {
			return p
		}
	}
	t.Skipf("no %s capture", contains)
	return ""
}

// Lab gates (Phase 1.4 on real bytes; needs C2PARSER_TESTDATA, nothing is
// written to the repo): re-time the Havoc session in http_c2_enum to its
// own schedule (findings identical) and to a model (bytes identical per
// transaction); re-address and 0 % damage are no-ops; splicing the session
// into part2's background never lowers its score.
func TestLabTransforms(t *testing.T) {
	in, err := Read(labCapture(t, "http_c2_enum"))
	if err != nil {
		t.Fatal(err)
	}
	orig := analyze(t, in, engine.Config{})
	ch := channelOf(t, orig)
	txns := Transactions(in, ch)
	t.Logf("channel %v → %v:%d: %d transactions", ch.Client, ch.Server, ch.Port, len(txns))
	starts := make([]time.Time, len(txns))
	for i, x := range txns {
		starts[i] = x.Start
	}
	same, _, err := RetimeTo(in, ch, starts)
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range cfgs {
		if a, b := titles(analyze(t, in, cfg)), titles(analyze(t, same, cfg)); strings.Join(a, "\n") != strings.Join(b, "\n") {
			t.Errorf("%s: re-time to original changed findings\n %v\n %v", eng(cfg), a, b)
		}
	}
	for _, model := range []synth.Timing{{Model: "shortening", Sleep: 60, Jitter: 0.2}, {Model: "lengthening", Sleep: 30, Jitter: 0.5}, {Model: "anchored", Sleep: 300, Jitter: 0.1}} {
		out, c, err := Retime(in, ch, model, synth.Artifacts{}, 1)
		if err != nil {
			t.Fatal(err)
		}
		after := Transactions(out, ch)
		for i := range txns {
			if i >= len(after) || txns[i].ReqBytes != after[i].ReqBytes || txns[i].RespBytes != after[i].RespBytes {
				t.Fatalf("%s: transaction %d bytes changed", model.Model, i)
			}
		}
		for _, cfg := range cfgs {
			f := channelFinding(analyze(t, out, cfg), ch)
			t.Logf("%s %s re-timed (%s): %v", eng(cfg), model.Model, c.Detail, scoreOrNil(f))
		}
	}
	m := remapAll(in)
	moved, _, _ := Readdress(in, m)
	for _, cfg := range cfgs {
		if a, b := scores(analyze(t, in, cfg)), scores(analyze(t, moved, cfg)); strings.Join(a, "\n") != strings.Join(b, "\n") {
			t.Errorf("%s: lab re-address changed scores\n %v\n %v", eng(cfg), a, b)
		}
	}
	z, _ := Drop(in, 0, 1)
	if !bytes.Equal(pcapBytes(t, z), pcapBytes(t, in)) {
		t.Error("lab drop 0 % not a no-op")
	}
	bgPath := labCapture(t, "part2")
	bg, err := Read(bgPath)
	if err != nil {
		t.Fatal(err)
	}
	mix, _, err := Splice(bg, in, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range cfgs {
		before := channelFinding(analyze(t, in, cfg), ch)
		after := channelFinding(analyze(t, mix, cfg), ch)
		if before == nil || after == nil || after.Score < before.Score-1e-9 {
			t.Errorf("%s: splice lowered the C2 score: %v → %v", eng(cfg), scoreOrNil(before), scoreOrNil(after))
		}
	}
}

func channelFinding(res *engine.Result, ch Channel) *engine.Finding {
	for i := range res.Findings {
		f := &res.Findings[i]
		if f.Category == engine.CatC2 && f.Client == ch.Client.String() && strings.HasPrefix(f.Server, ch.Server.String()) {
			return f
		}
	}
	return nil
}

func scoreOrNil(f *engine.Finding) string {
	if f == nil {
		return "none"
	}
	return fmt.Sprintf("%.2f", f.Score)
}
