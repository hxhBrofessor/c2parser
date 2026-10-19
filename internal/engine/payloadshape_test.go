package engine

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"c2parser/internal/stats"
	sy "c2parser/internal/synth"
)

func residueDetail(res *Result, server string) string {
	for i := range res.Findings {
		f := &res.Findings[i]
		if !strings.Contains(f.Title, server) {
			continue
		}
		for _, s := range f.Signals {
			if s.Name == "length_residue" {
				return s.Detail
			}
		}
	}
	return ""
}

// The corpus channels with a known class measure it, in the right
// direction and modulus.
func TestLengthResidueCorpus(t *testing.T) {
	for _, tc := range []struct{ scenario, server, want string }{
		{"shape-residue-http-12", "198.51.100.121", "≡ 12 (mod 16)"},
		{"shape-smb-pipe-framed", "10.5.0.30", "≡ 4 (mod 16)"},
	} {
		sc, err := sy.LoadScenario("../../corpus/scenarios/" + tc.scenario + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		for _, cfg := range []Config{{}, {TimingV2: true}} {
			if d := residueDetail(analyzeScenario(t, sc, cfg), tc.server); !strings.Contains(d, tc.want) {
				t.Errorf("%s v2=%v: %q, want %s", tc.scenario, cfg.TimingV2, d, tc.want)
			}
		}
	}
	// QUIC is never measured; benign browsing has no class.
	for _, name := range []string{"shape-quic-redirectors-3", "benign-models", "shape-artifacts-http"} {
		sc, err := sy.LoadScenario("../../corpus/scenarios/" + name + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range analyzeScenario(t, sc, Config{TimingV2: true}).Findings {
			for _, s := range f.Signals {
				if s.Name == "length_residue" {
					t.Errorf("%s: length_residue on %s: %s", name, f.Title, s.Detail)
				}
			}
		}
	}
}

// postChannel: n POSTs with body(i) and response resp(i).
func postChannel(t *testing.T, n int, ctype string, body func(i int) string) *Result {
	t.Helper()
	return carrierChannel(t, n, func(i int) carrierMsg {
		return carrierMsg{respHdrs: []string{"Content-Type: " + ctype}, body: body(i)}
	})
}

func TestLengthResidueChannel(t *testing.T) {
	r := seeded(131, 132)
	aligned := func(i int) int { return 16 * (4 + r.IntN(25)) } // ≡ 0 mod 16, varied, ≤ 448 B
	cases := []struct {
		name  string
		ctype string
		body  func(i int) string
		want  string // "" = no signal
	}{
		{"raw random, ≡0 mod 16", "application/octet-stream", func(i int) string { return string(rbytes(r, aligned(i))) }, "≡ 0 (mod 16)"},
		{"base64 random, ≡8 mod 16", "text/plain", func(i int) string {
			return base64.StdEncoding.EncodeToString(rbytes(r, 8+16*(2+r.IntN(15))))
		}, "≡ 8 (mod 16)"},
		{"raw random, uniform lengths", "application/octet-stream", func(i int) string { return string(rbytes(r, 60+r.IntN(400))) }, ""},
		{"JSON text with aligned lengths", "application/json", func(i int) string {
			n := aligned(i)
			s := fmt.Sprintf(`{"id":%d,"items":"`, i)
			return s + strings.Repeat("ok, ", n)[:n-len(s)-2] + `"}`
		}, ""},
		{"fixed-size random heartbeat", "application/octet-stream", func(i int) string { return string(rbytes(r, 128)) }, ""},
		{"opaque image bodies", "image/png", func(i int) string { return string(rbytes(r, aligned(i))) }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := residueDetail(postChannel(t, 30, tc.ctype, tc.body), "203.0.113.77")
			if tc.want == "" && d != "" || tc.want != "" && !strings.Contains(d, tc.want) {
				t.Errorf("got %q, want %q", d, tc.want)
			}
			if tc.want != "" && !strings.Contains(d, "response body") {
				t.Errorf("direction: %q", d)
			}
		})
	}
}

// Mutation: the "encrypted-looking" gate is what keeps aligned plaintext
// from being measured; without it the JSON case reports a class.
func TestLengthResidueRandomGateMutation(t *testing.T) {
	r := seeded(141, 142)
	body := func(i int) string {
		n := 16 * (4 + r.IntN(25)) // ≤ 448 B: whole body retained
		s := fmt.Sprintf(`{"id":%d,"items":"`, i)
		return s + strings.Repeat("ok, ", n)[:n-len(s)-2] + `"}`
	}
	if d := residueDetail(postChannel(t, 30, "application/json", body), "203.0.113.77"); d != "" {
		t.Fatalf("JSON measured: %s", d)
	}
	residueRandomGate = false
	defer func() { residueRandomGate = true }()
	r = seeded(141, 142)
	if d := residueDetail(postChannel(t, 30, "application/json", body), "203.0.113.77"); !strings.Contains(d, "≡ 0 (mod 16)") {
		t.Errorf("mutation (no randomness gate) did not measure the aligned JSON: %q", d)
	}
}

// FuzzPayloadShape: arbitrary message sequences never panic, stay within
// the per-direction bound, and a reported signal is never critical alone.
func FuzzPayloadShape(f *testing.F) {
	f.Add([]byte("\x00\x10abcdefghijklmnop\x01\x20"), uint8(40))
	f.Add([]byte{5, 0, 0, 3}, uint8(3))
	f.Fuzz(func(t *testing.T, seed []byte, n uint8) {
		var p residuePair
		ch := &httpChannel{requests: 1, responses: 1}
		pf := &smbFile{Writes: 1}
		for i := 0; i < int(n); i++ {
			k := 0
			if len(seed) > 0 {
				k = int(seed[i%len(seed)])
			}
			msg := make([]byte, k*3+i%7)
			for j := range msg {
				msg[j] = byte(j*31 + i + k)
			}
			p.track(i%2).add(len(msg), msg, nil)
			m := &httpMsg{req: i%2 == 0, bodyLen: int64(len(msg))}
			m.addBody(msg)
			ch.noteHTTPResidue(m, false)
			pf.notePipeResidue(msg, i%2 == 0)
		}
		for _, pp := range []*residuePair{&p, ch.residue, pf.residue} {
			if pp == nil {
				continue
			}
			for _, tr := range pp {
				if tr != nil && len(tr.lens) > residueMaxMsgs {
					t.Fatal("unbounded")
				}
			}
			if sg, ok := lengthResidueSignal(pp, [2]string{"a", "b"}); ok && sg.Contribution() >= 0.85 {
				t.Fatalf("critical alone: %+v", sg)
			}
		}
	})
}

// v11a: every signal the new detectors emit has a named family (none
// lands in "unmapped"), on the scenarios that exercise them.
func TestV11aSignalsMapped(t *testing.T) {
	seen := map[string]bool{}
	for _, name := range []string{"shape-carrier-base32", "shape-carrier-base58", "shape-carrier-words", "shape-residue-http-12",
		"shape-smb-pipe-framed", "gate-fleet3-http-fixed-uri", "gate-fleet3-http-word-dot-ext"} {
		sc, err := sy.LoadScenario("../../corpus/scenarios/" + name + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		for _, cfg := range []Config{{}, {TimingV2: true}} {
			for _, f := range analyzeScenario(t, sc, cfg).Findings {
				for _, s := range f.Signals {
					if strings.HasPrefix(s.Name, "encoded_payload_in_") || strings.HasPrefix(s.Name, "uri_shape:") ||
						s.Name == "pivot_frame_header" || s.Name == "length_residue" || strings.Contains(s.Name, "mythic") {
						seen[s.Name] = true
						if stats.Unmapped(s.Name) {
							t.Errorf("%s: %s is unmapped", name, s.Name)
						}
						if _, ok := f.Families["unmapped"]; cfg.TimingV2 && ok && stats.Unmapped(s.Name) {
							t.Errorf("%s: unmapped family present", name)
						}
					}
				}
			}
		}
	}
	for _, want := range []string{"encoded_payload_in_query", "encoded_payload_in_resp", "uri_shape:fixed-uri", "uri_shape:word-dot-ext", "pivot_frame_header", "length_residue"} {
		if !seen[want] {
			t.Errorf("%s never emitted by the v11a scenarios", want)
		}
	}
}

// v11a remediation F06: the first eligible message counts. Exact 7 / 8 / 9
// boundaries on HTTP (both directions) and pipes, with no allocation for
// a single eligible message and none for ineligible ones.
func TestResidueFirstSampleBoundaries(t *testing.T) {
	lens := func(n int) []int {
		out := make([]int, n)
		for i := range out {
			out[i] = 64 + 16*i // ≡ 0 (mod 16), all distinct, CV > 0.05
		}
		return out
	}
	for _, n := range []int{7, 8, 9} {
		for _, req := range []bool{false, true} {
			r := seeded(171, uint64(n))
			ch := &httpChannel{}
			for _, l := range lens(n) {
				m := &httpMsg{req: req}
				m.addBody(rbytes(r, l))
				ch.noteHTTPResidue(m, false)
			}
			sg, ok := lengthResidueSignal(ch.residue, [2]string{"request body", "response body"})
			if ok != (n >= 8) {
				t.Errorf("HTTP req=%v n=%d: signal=%v (%s)", req, n, ok, sg.Detail)
			}
			if ok && !strings.Contains(sg.Detail, fmt.Sprintf("of %d messages", n)) {
				t.Errorf("HTTP req=%v n=%d: sample count: %s", req, n, sg.Detail)
			}
		}
		r := seeded(172, uint64(n))
		f := &smbFile{}
		for _, l := range lens(n) {
			f.notePipeResidue(rbytes(r, l), true)
		}
		if sg, ok := lengthResidueSignal(f.residue, [2]string{"pipe write", "pipe read"}); ok != (n >= 8) {
			t.Errorf("pipe n=%d: signal=%v (%s)", n, ok, sg.Detail)
		}
	}
	// a single eligible message allocates nothing (one-shot connections)
	ch := &httpChannel{}
	m := &httpMsg{}
	m.addBody(rbytes(seeded(1, 2), 300))
	ch.noteHTTPResidue(m, false)
	if ch.residue != nil || ch.residueFirst[1] != 300 {
		t.Errorf("one eligible message: tracker %v, first %v", ch.residue, ch.residueFirst)
	}
	// ineligible messages (empty, opaque, DCE/RPC) neither allocate nor
	// take the first slot
	ch = &httpChannel{}
	ch.noteHTTPResidue(&httpMsg{bodyLen: 0}, false)
	ch.noteHTTPResidue(m, true) // opaque
	f := &smbFile{}
	f.notePipeResidue(append([]byte{0x05, 0x00}, rbytes(seeded(3, 4), 70)...), true)
	if ch.residue != nil || ch.residueFirst != (residueFirst{}) || f.residue != nil || f.residFirst != (residueFirst{}) {
		t.Errorf("ineligible samples changed state: %v %v %v %v", ch.residue, ch.residueFirst, f.residue, f.residFirst)
	}
	// duplicate lengths: 9 messages but 7 distinct → not measurable
	ch = &httpChannel{}
	r := seeded(5, 6)
	for _, l := range []int{64, 64, 80, 96, 112, 128, 144, 160, 160} {
		m := &httpMsg{}
		m.addBody(rbytes(r, l))
		ch.noteHTTPResidue(m, false)
	}
	if _, ok := lengthResidueSignal(ch.residue, [2]string{"a", "b"}); ok {
		t.Error("7 distinct lengths measured")
	}
}

// Pipe records merged by consolidate keep a pending first sample.
func TestResidueFirstSampleMerge(t *testing.T) {
	r := seeded(9, 9)
	a, b := &smbFile{sigs: map[string]int{}}, &smbFile{sigs: map[string]int{}}
	a.notePipeResidue(rbytes(r, 64), true) // pending only
	for i := 1; i < 8; i++ {
		b.notePipeResidue(rbytes(r, 64+16*i), true)
	}
	a.mergeFrom(b)
	if sg, ok := lengthResidueSignal(a.residue, [2]string{"pipe write", "pipe read"}); !ok || !strings.Contains(sg.Detail, "of 8 messages") {
		t.Errorf("merged pending first sample: %v %q", ok, sg.Detail)
	}
}
