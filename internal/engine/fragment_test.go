package engine

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	sy "c2parser/internal/synth"
)

// v11a remediation F03 (recovery audit): response-body word-run
// detection must not depend on TCP segment or chunk boundaries.

// feedSplit feeds body to a fresh response message, the first fragment
// being first bytes long and the rest in fragments of size rest.
func feedSplit(body []byte, first, rest int) *httpMsg {
	m := &httpMsg{}
	if first > len(body) {
		first = len(body)
	}
	m.addBody(body[:first])
	for b := body[first:]; len(b) > 0; {
		n := min(rest, len(b))
		m.addBody(b[:n])
		b = b[n:]
	}
	return m
}

// Unit level: every first-fragment size 1..80 (and 1-byte trickle) gives
// exactly the histogram of the unsplit body — the buffered prefix is
// replayed once, never twice, never skipped.
func TestBodyWordsFragmentationEquivalence(t *testing.T) {
	r := seeded(201, 202)
	for k := 0; k < 5; k++ {
		body := []byte(sy.Words(rbytes(r, 200)))
		whole := feedSplit(body, len(body), 1)
		wh, ok := whole.words.result()
		if !ok {
			t.Fatal("unsplit word body not accepted")
		}
		for first := 1; first <= 80; first++ {
			for _, rest := range []int{1, 3, 7, 1400} {
				m := feedSplit(body, first, rest)
				if m.words == nil {
					t.Fatalf("first=%d rest=%d: not admitted", first, rest)
				}
				h, ok := m.words.result()
				if !ok || h.N != wh.N || h.Counts != wh.Counts {
					t.Fatalf("first=%d rest=%d: histogram differs (N %d vs %d)", first, rest, h.N, wh.N)
				}
				if string(m.head) != string(whole.head) || m.bodyLen != whole.bodyLen {
					t.Fatalf("first=%d rest=%d: retained head / length differ", first, rest)
				}
			}
		}
	}
	// non-word bodies never yield a word-run result, and the admission
	// outcome is the same however they are split
	for _, body := range []string{`{"thumbnail":"` + base64.StdEncoding.EncodeToString(rbytes(r, 300)) + `"}`,
		"<!doctype html><html><body>" + strings.Repeat("Hello World ", 40) + "</body></html>",
		"The quick brown fox, jumps over the lazy dog. " + sy.Words(rbytes(r, 100)),
		string(rbytes(r, 300))} {
		whole := feedSplit([]byte(body), len(body), 1)
		for first := 1; first <= 70; first++ {
			m := feedSplit([]byte(body), first, 5)
			if (m.words == nil) != (whole.words == nil) {
				t.Fatalf("%.20q first=%d: admission differs from the unsplit body", body, first)
			}
			if m.words != nil {
				if _, ok := m.words.result(); ok {
					t.Fatalf("%.20q first=%d: non-word body accepted as a word run", body, first)
				}
			}
		}
	}
	// a word run longer than the admission window but with a non-word
	// byte inside the window is rejected, not left pending
	m := feedSplit([]byte("Abc Def Ghi Jkl"), 15, 1)
	if m.words == nil {
		t.Error("three breaks in the first bytes must admit")
	}
	m = feedSplit([]byte(strings.Repeat("A", 70)), 1, 1)
	if m.words != nil || !m.wordsDone {
		t.Error("64 bytes without a break must reject")
	}
}

// splitChannel writes 12 request/response pairs; each response is sent
// as header+first body bytes in one TCP segment and the remainder in
// another (first < 0: unsplit).
func splitChannel(t *testing.T, first int, body func(i int) string, ctype string, cfg Config) *Result {
	t.Helper()
	s := newSynth(t)
	r := seeded(11, 12)
	ts := s.now
	sess := s.tcp(ts, "10.1.1.20", 52000, "203.0.113.77", 80)
	for i := 0; i < 12; i++ {
		ts = ts.Add(time.Duration(5+r.IntN(40)) * time.Second)
		ts = sess.Send(ts, true, sy.HTTPReq("GET", "/", []string{"Host: carrier.example", "User-Agent: test/1.0"}, ""), 1400)
		resp := sy.HTTPResp("HTTP/1.1 200 OK", []string{"Content-Type: " + ctype}, body(i))
		hdrEnd := strings.Index(string(resp), "\r\n\r\n") + 4
		if first < 0 || hdrEnd+first >= len(resp) {
			ts = sess.Send(ts.Add(30*time.Millisecond), false, resp, 1400)
			continue
		}
		ts = sess.Send(ts.Add(30*time.Millisecond), false, resp[:hdrEnd+first], 1400)
		ts = sess.Send(ts.Add(time.Millisecond), false, resp[hdrEnd+first:], 1400)
	}
	sess.Close(ts.Add(time.Second))
	return s.analyze(cfg)
}

func respSummary(res *Result) string {
	f, d := carrierSignal(res, "encoded_payload_in_resp")
	if f == nil {
		return "no finding"
	}
	if i := strings.Index(d, ", e.g. "); i >= 0 {
		d = d[:i]
	}
	return fmt.Sprintf("%.2f %s | %s", f.Score, f.Severity, d)
}

// Capture level, both engines: single-segment and fragmented responses
// give identical response-carrier evidence and scores — word-run
// positives and benign negatives alike.
func TestResponseFragmentationEquivalence(t *testing.T) {
	bodies := []struct {
		name, ctype string
		mk          func() func(int) string
		positive    bool
	}{
		{"Sliver-format word run", "text/plain", func() func(int) string {
			r := seeded(41, 42)
			return func(int) string { return sy.Words(rbytes(r, 200)) }
		}, true},
		{"bare base64 body", "application/octet-stream", func() func(int) string {
			r := seeded(43, 44)
			return func(int) string { return base64.StdEncoding.EncodeToString(rbytes(r, 300)) }
		}, true},
		{"prose (word run, not random)", "text/plain", func() func(int) string {
			r := seeded(45, 46)
			words := strings.Fields("The quick brown Fox jumps over the lazy Dog and then the Dog sleeps in the warm Sun while the Fox runs off into the dark Woods to find some food for the night")
			return func(int) string {
				w := append([]string{}, words...)
				r.Shuffle(len(w), func(a, b int) { w[a], w[b] = w[b], w[a] })
				return strings.Join(append(w, w...), " ")
			}
		}, false},
		{"JSON thumbnail (F02 control)", "application/json", func() func(int) string {
			r := seeded(151, 152)
			return func(int) string { return `{"thumbnail":"` + base64.StdEncoding.EncodeToString(rbytes(r, 300)) + `"}` }
		}, false},
	}
	for _, b := range bodies {
		for _, cfg := range []Config{{}, {TimingV2: true}} {
			want := respSummary(splitChannel(t, -1, b.mk(), b.ctype, cfg))
			if b.positive != strings.Contains(want, "encoded_payload_in_resp") && b.positive != strings.Contains(want, "responses carry") {
				t.Errorf("%s v2=%v unsplit: %s", b.name, cfg.TimingV2, want)
			}
			for _, first := range []int{0, 1, 2, 5, 63, 64, 65, 200} {
				if got := respSummary(splitChannel(t, first, b.mk(), b.ctype, cfg)); got != want {
					t.Errorf("%s v2=%v first body segment %d B:\n  got  %s\n  want %s", b.name, cfg.TimingV2, first, got, want)
				}
			}
			t.Logf("%-32s v2=%-5v %s", b.name, cfg.TimingV2, want)
		}
	}
}

// FuzzBodyWordsFragmentation: for any body and any fragmentation the
// streamed decoder's admission and result equal the unsplit body's, and
// its state stays bounded (one 256-bin histogram, nothing buffered beyond
// the retained head).
func FuzzBodyWordsFragmentation(f *testing.F) {
	f.Add([]byte(sy.Words(rbytes(seeded(1, 2), 60))), uint8(1), uint8(3))
	f.Add([]byte("Abc Def Ghi Jkl"), uint8(2), uint8(1))
	f.Add([]byte("Foo\nBar Baz Qux Quux"), uint8(5), uint8(2))
	f.Fuzz(func(t *testing.T, body []byte, first, rest uint8) {
		if len(body) > 4096 {
			body = body[:4096]
		}
		whole := feedSplit(body, len(body), 1)
		m := feedSplit(body, int(first)+1, int(rest)+1)
		if (m.words == nil) != (whole.words == nil) || m.wordsDone != whole.wordsDone {
			t.Fatalf("admission differs: split %v/%v unsplit %v/%v", m.words != nil, m.wordsDone, whole.words != nil, whole.wordsDone)
		}
		if m.words != nil {
			h1, ok1 := m.words.result()
			h2, ok2 := whole.words.result()
			if ok1 != ok2 || ok1 && (h1.N != h2.N || h1.Counts != h2.Counts) {
				t.Fatal("result differs")
			}
		}
		if len(m.head) > headSample {
			t.Fatal("head unbounded")
		}
	})
}
