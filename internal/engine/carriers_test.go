package engine

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	mrand "math/rand/v2"
	"net/url"
	"strings"
	"testing"
	"time"

	"c2parser/internal/stats"
	sy "c2parser/internal/synth"
)

// v11a N1: carrier decoder and channel tests. The v10 decoder is kept
// here verbatim as the reference for the "existing labels unchanged"
// property (decodeTokenV10 is a copy of c2parser-v10.0 decodeToken).

func decodeTokenV10(v string) ([]byte, string) {
	if u, err := url.QueryUnescape(v); err == nil {
		v = u
	}
	if len(v)%2 == 0 && isHexToken(v) {
		if b, err := hex.DecodeString(v); err == nil {
			return b, "hex"
		}
	}
	if b, ok := netbiosDecode(v); ok {
		return b, "netbios"
	}
	run := ""
	for _, r := range b64Run.FindAllString(v, 8) {
		if len(r) > len(run) {
			run = r
		}
	}
	if run != "" && len(run)*4 >= len(v)*3 {
		if b, enc := decodeB64(run); b != nil {
			return b, enc
		}
	}
	return []byte(v), "raw"
}

func seeded(a, b uint64) *mrand.Rand { return mrand.New(mrand.NewPCG(a, b)) }

func rbytes(r *mrand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.IntN(256))
	}
	return b
}

var b32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

func TestDecodeTokenV10LabelsUnchanged(t *testing.T) {
	r := seeded(1, 2)
	raw := rbytes(r, 96)
	nb := make([]byte, 0, 2*len(raw))
	for _, c := range raw {
		nb = append(nb, 'a'+c>>4, 'a'+c&0x0f)
	}
	for _, tc := range []struct{ name, tok, want, pre, suf string }{
		{"hex", hex.EncodeToString(raw), "hex", "", ""},
		{"netbios", string(nb), "netbios", "", ""},
		{"netbiosu", strings.ToUpper(string(nb)), "netbios", "", ""},
		{"base64", strings.ReplaceAll(base64.StdEncoding.EncodeToString(raw), "+", "A"), "base64", "", ""}, // no '+': TestDecodeTokenV10PlusIsSpace
		{"base64url", base64.RawURLEncoding.EncodeToString(raw), "base64url", "", ""},
		{"base64url wrapped", "SESSIONID=" + base64.RawURLEncoding.EncodeToString(raw) + ";v=1", "base64url", "SESSIONID=", ";v=1"},
		{"raw text", "this is plain text, not an encoding", "raw", "", ""},
	} {
		got, enc, pre, suf := decodeTokenWrap(tc.tok)
		want, wenc := decodeTokenV10(tc.tok)
		if enc != tc.want || wenc != tc.want || !bytes.Equal(got, want) {
			t.Errorf("%s: got %s, v10 %s, want %s (bytes equal %v)", tc.name, enc, wenc, tc.want, bytes.Equal(got, want))
		}
		if pre != tc.pre || suf != tc.suf {
			t.Errorf("%s: wrapper %q/%q, want %q/%q", tc.name, pre, suf, tc.pre, tc.suf)
		}
	}
}

// Pre-existing v10 behaviour, pinned so v11a provably leaves it alone:
// every request token is query-unescaped, so a standard-base64 '+' becomes
// a space and the token no longer decodes. Response tokens (v11a) are not
// URL-encoded and skip the unescape. Recorded in docs/review-v11a.md as a
// follow-up; fixing it would change existing request findings.
func TestDecodeTokenV10PlusIsSpace(t *testing.T) {
	tok := "ab+" + base64.RawStdEncoding.EncodeToString(rbytes(seeded(9, 9), 90))
	if _, enc := decodeToken(tok); enc != "raw" {
		t.Errorf("request token with '+': %s, v10 gives raw", enc)
	}
	if _, enc, _, _ := decodeRespToken(tok); enc != "base64" {
		t.Errorf("response token with '+': %s, want base64", enc)
	}
}

// v11a remediation F04: ambiguous-alphabet tokens (base32, base58, and
// canonical base64 drawn from the base58 alphabet) keep v10's label and
// bytes exactly; there is no base32 / base58 label anywhere.
func TestDecodeTokenAmbiguousAlphabets(t *testing.T) {
	r := seeded(3, 4)
	raw := rbytes(r, 120)
	for _, tc := range []struct{ name, tok string }{
		{"base32 upper", b32NoPad.EncodeToString(raw)},
		{"base32 lower padded", strings.ToLower(base32.StdEncoding.EncodeToString(raw[:118]))},
		{"base32 with 6 '=' of padding", base32.StdEncoding.EncodeToString(raw[:1])},
		{"base58", sy.Base58(raw)},
		{"base58 leading zeros", sy.Base58(append([]byte{0, 0, 0}, raw...))},
		{"reviewer overlap token", strings.Repeat("Abc123XYZ789", 16)},
		{"canonical base64 over the base58 alphabet", canonicalB64FromB58(r, 280)},
		{"wrapped base58", "id:" + sy.Base58(raw) + ";"},
	} {
		b, enc, _, _ := decodeTokenWrap(tc.tok)
		old, oenc := decodeTokenV10(tc.tok)
		if enc != oenc || !bytes.Equal(b, old) {
			t.Errorf("%s: %s/%d bytes, v10 %s/%d bytes", tc.name, enc, len(b), oenc, len(old))
		}
		if enc == "base32" || enc == "base58" {
			t.Errorf("%s: alternative label %s", tc.name, enc)
		}
	}
}

// Malformed inputs decode exactly as v10 (raw or v10's partial decode).
func TestDecodeTokenMalformedMatchesV10(t *testing.T) {
	r := seeded(5, 7)
	b64 := base64.StdEncoding.EncodeToString(rbytes(r, 90))
	for _, tok := range []string{
		b64[:len(b64)-3] + "=" + b64[len(b64)-2:], // '=' inside
		b64 + "A",                         // length ≡ 1 mod 4
		strings.ReplaceAll(b64, "A", "!"), // invalid characters
		"%zz" + b64,                       // bad escape
		strings.Repeat("=", 40),
		"",
		hex.EncodeToString(rbytes(r, 40)) + "g", // odd hex
		netbiosOf(rbytes(r, 40))[1:],            // odd netbios
		strings.Repeat("Ab ", 30) + "\x00",
	} {
		b, enc := decodeToken(tok)
		old, oenc := decodeTokenV10(tok)
		if enc != oenc || !bytes.Equal(b, old) {
			t.Errorf("%.30q: %s, v10 %s", tok, enc, oenc)
		}
	}
}

// Word runs: the only new per-token decoding, for tokens v10 left raw;
// separators as in the snapshot's Decode (split on ' ', empty pieces
// skipped, each piece trimmed).
func TestDecodeTokenWordRunsSourceFormat(t *testing.T) {
	raw := rbytes(seeded(3, 5), 120)
	w := sy.Words(raw)
	for _, tc := range []struct {
		name, tok string
		ok        bool
	}{
		{"single spaces (Encode's format)", w, true},
		{"form-encoded spaces", strings.ReplaceAll(w, " ", "+"), true},
		{"doubled spaces: empty pieces skipped", strings.ReplaceAll(w, " ", "  "), true},
		{"CRLF after a word, before the space", strings.Replace(w, " ", "\r\n ", 5), true},
		{"newline after the space", strings.Replace(w, " ", " \n", 5), true},
		{"trailing CRLF", w + "\r\n", true},
		{"newline-only separation (one Sliver piece)", strings.ReplaceAll(w, " ", "\n"), false},
		{"tab inside a piece", strings.Replace(w, " ", "\t", 3), false},
	} {
		got, enc := decodeToken(tc.tok)
		if ok := enc == "english" && bytes.Equal(got, raw); ok != tc.ok {
			t.Errorf("%s: %s (bytes equal %v), want accepted=%v", tc.name, enc, bytes.Equal(got, raw), tc.ok)
		}
	}
}

// F03: Sliver's SumWord is case sensitive; uppercase and mixed-case words
// decode to their own sums, never to the lowercased word's.
func TestWordRunCaseSensitiveSums(t *testing.T) {
	words := []string{"Apple", "APPLE", "apple", "ApPlE", "Zebra", "Quixotic", "A", "Z", "aZ", "Za"}
	var toks []string
	var want []byte
	for i := 0; i < 30; i++ {
		w := words[i%len(words)]
		toks = append(toks, w)
		s := 0
		for _, c := range []byte(w) {
			s += int(c)
		}
		want = append(want, byte(s))
	}
	got, enc := decodeToken(strings.Join(toks, " "))
	if enc != "english" || !bytes.Equal(got, want) {
		t.Fatalf("case-sensitive sums: %s %v, want %v", enc, got, want)
	}
	if got[0] == got[2] || got[1] == got[2] {
		t.Errorf("Apple / APPLE / apple must decode differently: %v", got[:3])
	}
}

func TestDecodeTokenStrictNegatives(t *testing.T) {
	r := seeded(5, 6)
	raw := rbytes(r, 120)
	b64 := base64.StdEncoding.EncodeToString(raw)
	prose := "the quick brown fox jumps over the lazy dog and then the dog sleeps in the sun while the fox runs off into the woods to find some food"
	for _, tc := range []struct{ name, tok string }{
		{"23-word run", strings.Join(strings.Fields(prose)[:23], " ")},
		{"base64 text", b64},
		{"dot separators (not Sliver format)", strings.ReplaceAll(sy.Words(raw), " ", ".")},
		{"dash separators (v10 base64url, not a word run)", strings.ReplaceAll(sy.Words(raw), " ", "-")},
		{"punctuated prose", "The quick brown fox, jumping over the lazy dog, then sleeps; " + prose},
		{"digits inside words", strings.Replace(sy.Words(raw), " ", " a1 ", 2)},
	} {
		if _, enc := decodeToken(tc.tok); enc == "english" {
			t.Errorf("%s: decoded as a word run", tc.name)
		}
	}
	// prose decodes as a word run but is not random after decoding
	if d, enc := decodeToken(prose + " " + prose); enc != "english" {
		t.Errorf("prose: %s", enc)
	} else if a := stats.AssessBytes(d); a.Score >= 0.8 {
		t.Errorf("prose word sums look random: %+v", a)
	}
}

// Decoding work and output are bounded: a 64 KB word run decodes at most
// maxWords words; 64 KB ambiguous-alphabet tokens decode as v10 does, in
// one linear pass (no alternative decoding remains).
func TestDecodeTokenBounded(t *testing.T) {
	r := seeded(13, 14)
	w := sy.Words(rbytes(r, 9000))
	if b, enc := decodeToken(w); enc != "english" || len(b) != maxWords {
		t.Errorf("long word run: %s, %d bytes", enc, len(b))
	}
	big := sy.Base58(rbytes(r, 4096))
	for len(big) < 64<<10 {
		big += big
	}
	big = big[:64<<10]
	b, enc := decodeToken(big)
	old, oenc := decodeTokenV10(big)
	if enc != oenc || !bytes.Equal(b, old) || len(b) > len(big) {
		t.Errorf("64 KB base58-alphabet token: %s/%d, v10 %s/%d", enc, len(b), oenc, len(old))
	}
	if _, ok := decodeWordRun(strings.Repeat("A", 64<<10)); ok {
		t.Error("a 64 KB single 'word' is not a word run")
	}
}

// FuzzDecodeToken (F04 oracle, no exemptions): never panics, is
// deterministic, output is bounded by the input, and every token v10
// decoded keeps v10's label and bytes exactly. Only tokens v10 left raw
// may take the new word-run label.
func FuzzDecodeToken(f *testing.F) {
	r := seeded(7, 8)
	raw := rbytes(r, 80)
	for _, s := range []string{"", "a", hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw),
		b32NoPad.EncodeToString(raw), sy.Base58(raw), sy.Words(raw), "SESSIONID=" + base64.RawURLEncoding.EncodeToString(raw),
		"%zz%", "1111111111111111111111111111111111111111111111111111111111111111111", strings.Repeat("ab ", 40),
		strings.Repeat("Abc123XYZ789", 16), strings.ToUpper(sy.Words(raw)), strings.ReplaceAll(sy.Words(raw), " ", "\n")} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		b, enc, pre, suf := decodeTokenWrap(v)
		b2, enc2, pre2, suf2 := decodeTokenWrap(v)
		if enc != enc2 || pre != pre2 || suf != suf2 || !bytes.Equal(b, b2) {
			t.Fatal("nondeterministic")
		}
		if len(b) > len(v) {
			t.Fatalf("decoded %d bytes from %d", len(b), len(v))
		}
		old, oenc := decodeTokenV10(v)
		if oenc != "raw" && (enc != oenc || !bytes.Equal(b, old)) {
			t.Fatalf("v10 %s token became %s", oenc, enc)
		}
		if oenc == "raw" && enc != "raw" && enc != "english" {
			t.Fatalf("raw token became %s", enc)
		}
	})
}

// ------------------------------------------------- channel-level tests

type carrierMsg struct {
	uri      string
	reqHdrs  []string
	respHdrs []string
	body     string
}

// carrierChannel writes n request/response pairs on one keep-alive
// connection to 203.0.113.77 at irregular intervals.
func carrierChannel(t *testing.T, n int, mk func(i int) carrierMsg) *Result {
	t.Helper()
	return carrierChannelCfg(t, n, mk, Config{})
}

func carrierChannelCfg(t *testing.T, n int, mk func(i int) carrierMsg, cfg Config) *Result {
	t.Helper()
	s := newSynth(t)
	r := seeded(11, 12)
	ts := s.now
	sess := s.tcp(ts, "10.1.1.20", 52000, "203.0.113.77", 80)
	for i := 0; i < n; i++ {
		ts = ts.Add(time.Duration(5+r.IntN(40)) * time.Second)
		m := mk(i)
		uri := m.uri
		if uri == "" {
			uri = "/"
		}
		hdrs := append([]string{"Host: carrier.example", "User-Agent: test/1.0"}, m.reqHdrs...)
		ts = sess.Send(ts, true, sy.HTTPReq("GET", uri, hdrs, ""), 1400)
		rh := m.respHdrs
		if rh == nil {
			rh = []string{"Content-Type: application/octet-stream"}
		}
		ts = sess.Send(ts.Add(30*time.Millisecond), false, sy.HTTPResp("HTTP/1.1 200 OK", rh, m.body), 1400)
	}
	sess.Close(ts.Add(time.Second))
	return s.analyze(cfg)
}

func carrierSignal(res *Result, name string) (*Finding, string) {
	f := findBy(res, CatC2, "203.0.113.77")
	if f == nil {
		f = findBy(res, CatC2, "carrier.example")
	}
	if f == nil {
		for i := range res.Findings {
			if strings.Contains(res.Findings[i].Title, "203.0.113.77") {
				f = &res.Findings[i]
			}
		}
	}
	if f == nil {
		return nil, ""
	}
	for _, s := range f.Signals {
		if s.Name == name {
			return f, s.Detail
		}
	}
	return f, ""
}

func enc(kind string, b []byte) string {
	switch kind {
	case "base32":
		return b32NoPad.EncodeToString(b)
	case "base58":
		return sy.Base58(b)
	case "english":
		return sy.Words(b)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestCarrierRequestEncodings(t *testing.T) {
	// base32 / base58: TestCarrierChannelV10Compatibility (v10 labels)
	for _, kind := range []string{"base64", "english"} {
		t.Run(kind, func(t *testing.T) {
			r := seeded(21, uint64(len(kind)))
			res := carrierChannel(t, 12, func(i int) carrierMsg {
				e := enc(kind, rbytes(r, 200))
				if kind == "base64" { // v10 unescapes twice: '+' is lost (TestDecodeTokenV10PlusIsSpace)
					e = base64.RawURLEncoding.EncodeToString(rbytes(r, 200))
				}
				q := url.QueryEscape(e)
				return carrierMsg{uri: "/search?d=" + q, body: "ok"}
			})
			f, d := carrierSignal(res, "encoded_payload_in_query")
			if d == "" {
				t.Fatalf("%s in a query parameter: no encoded_payload_in_query: %v", kind, f)
			}
			want := kind
			if kind == "base64" {
				want = "base64url"
			}
			if !strings.Contains(d, "("+want+"×12)") {
				t.Errorf("label: %s", d)
			}
		})
	}
}

func TestCarrierResponseEncodings(t *testing.T) {
	for _, tc := range []struct {
		kind string
		hdr  bool // in a response header instead of the body
	}{{"base64", false}, {"base64", true}, {"english", true}, {"english", false}} { // base32/base58: TestCarrierChannelV10Compatibility
		where := map[bool]string{false: "body", true: "header"}[tc.hdr]
		t.Run(tc.kind+"-"+where, func(t *testing.T) {
			r := seeded(31, uint64(len(tc.kind)))
			mk := func(i int) carrierMsg {
				e := enc(tc.kind, rbytes(r, 200))
				if tc.hdr {
					return carrierMsg{respHdrs: []string{"Content-Type: text/plain", "X-Data: " + e}, body: "ok"}
				}
				return carrierMsg{body: e}
			}
			res := carrierChannel(t, 12, mk)
			f, d := carrierSignal(res, "encoded_payload_in_resp")
			if d == "" {
				t.Fatalf("%s in a response %s: no encoded_payload_in_resp: %v", tc.kind, where, f)
			}
			if !strings.Contains(d, "("+tc.kind+"×12)") || !strings.Contains(d, "12/12 responses") {
				t.Errorf("detail: %s", d)
			}
			// mutation: without response carriers the signal is gone
			defer func() { carrierResponses = true }()
			carrierResponses = false
			r = seeded(31, uint64(len(tc.kind)))
			if _, d := carrierSignal(carrierChannel(t, 12, mk), "encoded_payload_in_resp"); d != "" {
				t.Errorf("mutation (no response carriers) still fires: %s", d)
			}
		})
	}
}

// v11a remediation F03: word runs in a response body fire, from the
// bounded streamed decoder (it sees every body byte; only a 256-bin
// histogram is kept), in both engines. Before the fix this was a
// logging-only "limit" test.
func TestCarrierWordRunBody(t *testing.T) {
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		r := seeded(41, 42)
		mk := func(i int) carrierMsg { return carrierMsg{body: sy.Words(rbytes(r, 200))} }
		f, d := carrierSignal(carrierChannelCfg(t, 12, mk, cfg), "encoded_payload_in_resp")
		if !strings.Contains(d, "12/12 responses") || !strings.Contains(d, "(english×12)") {
			t.Fatalf("v2=%v: word-run body: %q", cfg.TimingV2, d)
		}
		t.Logf("v2=%v: %.2f %s", cfg.TimingV2, f.Score, d)
		// mutation: without the streamed decoder the 512-byte prefix is
		// too short and the signal disappears
		streamBodyWords = false
		r = seeded(41, 42)
		_, d = carrierSignal(carrierChannelCfg(t, 12, mk, cfg), "encoded_payload_in_resp")
		streamBodyWords = true
		if d != "" {
			t.Errorf("v2=%v: mutation (no streamed body decoder) still fires: %s", cfg.TimingV2, d)
		}
	}
}

// Chunked bodies with words split across chunk boundaries decode the same.
func TestCarrierWordRunBodyChunked(t *testing.T) {
	r := seeded(43, 44)
	s := newSynth(t)
	ts := s.now
	sess := s.tcp(ts, "10.1.1.20", 52000, "203.0.113.77", 80)
	for i := 0; i < 12; i++ {
		ts = ts.Add(time.Duration(5+r.IntN(40)) * time.Second)
		ts = sess.Send(ts, true, sy.HTTPReq("GET", "/", []string{"Host: carrier.example", "User-Agent: test/1.0"}, ""), 1400)
		body := sy.Words(rbytes(r, 200))
		var b strings.Builder
		b.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n")
		for len(body) > 0 {
			n := min(len(body), 37+r.IntN(50)) // boundaries fall mid-word
			fmt.Fprintf(&b, "%x\r\n%s\r\n", n, body[:n])
			body = body[n:]
		}
		b.WriteString("0\r\n\r\n")
		ts = sess.Send(ts.Add(30*time.Millisecond), false, []byte(b.String()), 211)
	}
	sess.Close(ts.Add(time.Second))
	if _, d := carrierSignal(s.analyze(Config{}), "encoded_payload_in_resp"); !strings.Contains(d, "(english×12)") {
		t.Errorf("chunked word-run body: %q", d)
	}
}

// Word-run body ramp keeps the v10 variability guard; prose bodies (a word
// run, but not random after decoding) never fire.
func TestCarrierWordRunBodyGuards(t *testing.T) {
	for _, tc := range []struct {
		n    int
		want float64
	}{{4, 0}, {5, 0.2}, {13, 1}} {
		r := seeded(45, uint64(tc.n))
		f, _ := carrierSignal(carrierChannel(t, tc.n, func(i int) carrierMsg { return carrierMsg{body: sy.Words(rbytes(r, 200))} }), "encoded_payload_in_resp")
		got := 0.0
		if f != nil {
			for _, s := range f.Signals {
				if s.Name == "encoded_payload_in_resp" {
					got = s.Score
				}
			}
		}
		if got != tc.want {
			t.Errorf("%d word-run bodies: %.2f, want %.2f", tc.n, got, tc.want)
		}
	}
	prose := strings.Fields("The quick brown Fox jumps over the lazy Dog and then the Dog sleeps in the warm Sun while the Fox runs off into the dark Woods to find some food for the night")
	r := seeded(46, 47)
	_, d := carrierSignal(carrierChannel(t, 12, func(i int) carrierMsg {
		w := append([]string{}, prose...)
		r.Shuffle(len(w), func(a, b int) { w[a], w[b] = w[b], w[a] })
		return carrierMsg{respHdrs: []string{"Content-Type: text/plain"}, body: strings.Join(append(w, w...), " ")}
	}), "encoded_payload_in_resp")
	if d != "" {
		t.Errorf("prose bodies fired: %s", d)
	}
}

// Bounded state: the streamed decoder is allocated only for word-like
// bodies; JSON / HTML / binary bodies never allocate one.
func TestBodyWordsAllocation(t *testing.T) {
	for body, want := range map[string]bool{
		sy.Words(rbytes(seeded(1, 1), 40)): true,
		`{"thumbnail":"AAAA"}`:             false,
		"<!doctype html><html>":            false,
		string([]byte{0x17, 3, 3, 0, 40}):  false,
		"Hello":                            false, // too few word breaks
	} {
		m := &httpMsg{}
		m.addBody([]byte(body))
		if (m.words != nil) != want {
			t.Errorf("%.20q: allocated=%v, want %v", body, m.words != nil, want)
		}
	}
	m := &httpMsg{req: true}
	m.addBody([]byte(sy.Words(rbytes(seeded(1, 1), 40))))
	if m.words != nil {
		t.Error("request bodies are not carriers: no decoder")
	}
}

// All 256 byte values decode from capitalised / mixed-case words built
// to the snapshot's SumWord rule (our own words; the reviewer's probe
// checks the snapshot dictionary itself, outside the repository).
func TestWordRunAllResidues(t *testing.T) {
	want := make([]byte, 256)
	for i := range want {
		want[i] = byte(i)
	}
	got, enc := decodeToken(sy.Words(want))
	if enc != "english" || !bytes.Equal(got, want) {
		t.Fatalf("all residues: %s, equal %v", enc, bytes.Equal(got, want))
	}
	upper := 0
	for _, w := range strings.Fields(sy.Words(want)) {
		if strings.ToLower(w) != w {
			upper++
		}
	}
	if upper < 128 {
		t.Errorf("only %d/256 fixture words carry uppercase", upper)
	}
}

// v11a remediation F02: a fresh encoded value inside a structured
// response document is a field, not a carrier, unless the channel's
// requests carry encoded payload too. Bare encoded bodies and response
// headers still fire (TestCarrierResponseEncodings).
func TestCarrierStructuredResponseFields(t *testing.T) {
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		for _, tc := range []struct {
			name string
			mk   func(r *mrand.Rand) func(int) carrierMsg
			want bool
		}{
			{"reviewer JSON thumbnail", func(r *mrand.Rand) func(int) carrierMsg {
				return func(int) carrierMsg {
					return carrierMsg{respHdrs: []string{"Content-Type: application/json"},
						body: `{"thumbnail":"` + base64.StdEncoding.EncodeToString(rbytes(r, 300)) + `"}`}
				}
			}, false},
			{"large base64 value in JSON", func(r *mrand.Rand) func(int) carrierMsg {
				return func(int) carrierMsg {
					return carrierMsg{respHdrs: []string{"Content-Type: application/json"},
						body: `{"id":7,"blob":"` + base64.StdEncoding.EncodeToString(rbytes(r, 3000)) + `"}`}
				}
			}, false},
			{"HTML data URI", func(r *mrand.Rand) func(int) carrierMsg {
				return func(int) carrierMsg {
					return carrierMsg{respHdrs: []string{"Content-Type: text/html"},
						body: `<img src="data:image/png;base64,` + base64.StdEncoding.EncodeToString(rbytes(r, 400)) + `">`}
				}
			}, false},
			{"XML element", func(r *mrand.Rand) func(int) carrierMsg {
				return func(int) carrierMsg {
					return carrierMsg{respHdrs: []string{"Content-Type: application/xml"},
						body: `<d>` + base64.StdEncoding.EncodeToString(rbytes(r, 400)) + `</d>`}
				}
			}, false},
			{"mixed text and a short encoded run", func(r *mrand.Rand) func(int) carrierMsg {
				return func(int) carrierMsg {
					return carrierMsg{respHdrs: []string{"Content-Type: text/plain"},
						body: "status report for the nightly job follows; token " + base64.StdEncoding.EncodeToString(rbytes(r, 30)) + " end of report, all systems nominal and green"}
				}
			}, false},
			{"malformed base64 (bad characters)", func(r *mrand.Rand) func(int) carrierMsg {
				return func(int) carrierMsg {
					return carrierMsg{body: strings.ReplaceAll(base64.StdEncoding.EncodeToString(rbytes(r, 300)), "A", "!")}
				}
			}, false},
			{"JSON field + request-side encoded payload (corroborated)", func(r *mrand.Rand) func(int) carrierMsg {
				return func(int) carrierMsg {
					return carrierMsg{uri: "/api?d=" + base64.RawURLEncoding.EncodeToString(rbytes(r, 200)),
						respHdrs: []string{"Content-Type: application/json"},
						body:     `{"data":"` + base64.StdEncoding.EncodeToString(rbytes(r, 300)) + `"}`}
				}
			}, true},
			{"bare base64 body", func(r *mrand.Rand) func(int) carrierMsg {
				return func(int) carrierMsg { return carrierMsg{body: base64.StdEncoding.EncodeToString(rbytes(r, 300))} }
			}, true},
		} {
			res := carrierChannelCfg(t, 12, tc.mk(seeded(151, 152)), cfg)
			f, d := carrierSignal(res, "encoded_payload_in_resp")
			score := 0.0
			if f != nil {
				score = f.Score
			}
			t.Logf("v2=%-5v %-55s resp-carrier=%-5v finding=%.2f", cfg.TimingV2, tc.name, d != "", score)
			if (d != "") != tc.want {
				t.Errorf("v2=%v %s: encoded_payload_in_resp=%v, want %v: %s", cfg.TimingV2, tc.name, d != "", tc.want, d)
			}
			if tc.want && strings.HasPrefix(tc.name, "JSON field") && !strings.Contains(d, "structured-document fields") {
				t.Errorf("corroborated structured field not named in the detail: %s", d)
			}
		}
	}
}

// The reviewer's JSON fixture produces no C2 finding at all, as v10.
func TestCarrierReviewerJSONBaseline(t *testing.T) {
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		r := seeded(151, 152)
		res := carrierChannelCfg(t, 12, func(int) carrierMsg {
			return carrierMsg{respHdrs: []string{"Content-Type: application/json"},
				body: `{"thumbnail":"` + base64.StdEncoding.EncodeToString(rbytes(r, 300)) + `"}`}
		}, cfg)
		for _, f := range res.Findings {
			if f.Score >= 0.2 {
				t.Errorf("v2=%v: %.2f %s %v", cfg.TimingV2, f.Score, f.Title, signalNames(&f))
			}
		}
	}
}

func TestCarrierWrapperEvidence(t *testing.T) {
	r := seeded(51, 52)
	res := carrierChannel(t, 10, func(i int) carrierMsg {
		return carrierMsg{reqHdrs: []string{"X-Session: SESSIONID=" + base64.RawURLEncoding.EncodeToString(rbytes(r, 200))}, body: "ok"}
	})
	_, d := carrierSignal(res, "encoded_payload_in_header")
	if !strings.Contains(d, `constant prefix "SESSIONID="`) {
		t.Errorf("wrapper evidence missing: %q", d)
	}
	// varying wrapper: no constant-prefix claim
	res = carrierChannel(t, 10, func(i int) carrierMsg {
		return carrierMsg{reqHdrs: []string{fmt.Sprintf("X-Session: S%d=", i) + base64.RawURLEncoding.EncodeToString(rbytes(r, 200))}, body: "ok"}
	})
	if _, d := carrierSignal(res, "encoded_payload_in_header"); d == "" || strings.Contains(d, "constant prefix") {
		t.Errorf("varying wrapper: %q", d)
	}
}

func TestCarrierBenignNegatives(t *testing.T) {
	r := seeded(61, 62)
	static := base64.StdEncoding.EncodeToString(rbytes(r, 200))
	cases := []struct {
		name string
		mk   func(i int) carrierMsg
		sig  string
	}{
		{"static base64 cookie", func(i int) carrierMsg {
			return carrierMsg{reqHdrs: []string{"Cookie: pref=" + static}, body: "ok"}
		}, "encoded_payload_in_cookie"},
		{"HTML page with a fresh nonce", func(i int) carrierMsg {
			nonce := base64.StdEncoding.EncodeToString(rbytes(r, 32))
			return carrierMsg{respHdrs: []string{"Content-Type: text/html; charset=utf-8"},
				body: `<!doctype html><html><head><meta name="csrf-token" content="` + nonce + `"><title>Dashboard</title></head><body><div id="app">Loading the dashboard for your account, please wait.</div></body></html>`}
		}, "encoded_payload_in_resp"},
		{"CDN and trace id headers", func(i int) carrierMsg {
			return carrierMsg{respHdrs: []string{"Content-Type: application/json",
				"X-Request-Id: " + fmt.Sprintf("%x-%x", rbytes(r, 8), rbytes(r, 8)),
				"X-Amz-Cf-Id: " + base64.StdEncoding.EncodeToString(rbytes(r, 200)),
				"Traceparent: 00-" + hex.EncodeToString(rbytes(r, 16)) + "-" + hex.EncodeToString(rbytes(r, 8)) + "-01",
				"Set-Cookie: sid=" + base64.StdEncoding.EncodeToString(rbytes(r, 200)) + "; Path=/"},
				body: `{"status":"ok","items":[1,2,3]}`}
		}, "encoded_payload_in_resp"},
		{"raw random octet-stream body", func(i int) carrierMsg {
			return carrierMsg{body: string(rbytes(r, 400))}
		}, "encoded_payload_in_resp"},
		{"opaque image body that happens to be base64 text", func(i int) carrierMsg {
			return carrierMsg{respHdrs: []string{"Content-Type: image/png"}, body: base64.StdEncoding.EncodeToString(rbytes(r, 300))}
		}, "encoded_payload_in_resp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, d := carrierSignal(carrierChannel(t, 12, tc.mk), tc.sig); d != "" {
				t.Errorf("benign %s fired: %s", tc.name, d)
			}
		})
	}
}

// Mutation: the CDN/trace-id exclusion is what keeps a fresh random
// X-Amz-Cf-Id from counting; without it the benign case fires.
func TestCarrierRespIDExclusionMutation(t *testing.T) {
	r := seeded(63, 64)
	mk := func(i int) carrierMsg {
		return carrierMsg{respHdrs: []string{"Content-Type: application/json",
			"X-Amz-Cf-Id: " + base64.RawURLEncoding.EncodeToString(rbytes(r, 200))}, body: `{"ok":1}`}
	}
	if _, d := carrierSignal(carrierChannel(t, 12, mk), "encoded_payload_in_resp"); d != "" {
		t.Fatalf("benign CDN id fired: %s", d)
	}
	defer func(p []string) { respIDHeaderPrefixes = p }(respIDHeaderPrefixes)
	respIDHeaderPrefixes = nil
	if _, d := carrierSignal(carrierChannel(t, 12, mk), "encoded_payload_in_resp"); d == "" {
		t.Error("mutation (no id-header exclusion) did not fire — the benign test is vacuous")
	}
}

// The variability guard is unchanged: ≥ 5 messages, (n-3)/10 scaling.
func TestCarrierVariabilityGuardBoundary(t *testing.T) {
	for _, tc := range []struct {
		n    int
		want float64 // signal score, 0 = absent
	}{{4, 0}, {5, 0.2}, {13, 1}} {
		r := seeded(71, uint64(tc.n))
		// fixture: standard base64 bodies (unpadded base32 is ambiguous with
		// base64 and decodes as v10 does — TestCarrierChannelV10Compatibility)
		res := carrierChannel(t, tc.n, func(i int) carrierMsg { return carrierMsg{body: base64.StdEncoding.EncodeToString(rbytes(r, 200))} })
		f, _ := carrierSignal(res, "encoded_payload_in_resp")
		got := 0.0
		if f != nil {
			for _, s := range f.Signals {
				if s.Name == "encoded_payload_in_resp" {
					got = s.Score
				}
			}
		}
		if got != tc.want {
			t.Errorf("%d responses: score %.2f, want %.2f", tc.n, got, tc.want)
		}
	}
}
