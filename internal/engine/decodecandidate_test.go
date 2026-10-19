package engine

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sy "c2parser/internal/synth"
)

func candidateHTTPFile(t *testing.T, body string) string {
	t.Helper()
	s := newSynth(t)
	ts := s.now
	sess := s.tcp(ts, "10.1.1.20", 52000, "203.0.113.77", 80)
	ts = sess.Send(ts, true, sy.HTTPReq("GET", "/candidate", []string{"Host: candidate.example", "User-Agent: test"}, ""), 1400)
	ts = sess.Send(ts.Add(time.Millisecond), false, sy.HTTPResp("HTTP/1.1 200 OK", []string{"Content-Type: text/plain"}, body), 1400)
	sess.Close(ts.Add(time.Second))
	path := filepath.Join(t.TempDir(), "candidate.pcap")
	if err := os.WriteFile(path, s.buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCandidateKeepsV10PrimaryAndAddsPaddedBase32(t *testing.T) {
	raw := make([]byte, 31)
	for i := range raw {
		raw[i] = byte(17*i + 3)
	}
	token := base32.StdEncoding.EncodeToString(raw)
	if token != "AMKCKNSHLBUXVC44VW7M7YHRAIJSINKGK5UHTCU3VS645X7QAE======" {
		t.Fatalf("unexpected deterministic RFC 4648 token %q", token)
	}
	primary, primaryEncoding, _, _ := decodeRespToken(token)
	legacy, legacyEncoding := decodeTokenV10(token)
	if primaryEncoding != "base64" || legacyEncoding != primaryEncoding || !bytes.Equal(primary, legacy) || len(primary) != 37 {
		t.Fatalf("primary result changed: current=%s/%d v10=%s/%d", primaryEncoding, len(primary), legacyEncoding, len(legacy))
	}

	path := candidateHTTPFile(t, token)
	legacyResult, err := AnalyzeFile(path, Config{})
	if err != nil {
		t.Fatal(err)
	}
	withCandidates, candidateReport, err := AnalyzeFileWithCandidates(path, Config{})
	if err != nil {
		t.Fatal(err)
	}
	legacyJSON, _ := json.Marshal(legacyResult)
	withCandidatesJSON, _ := json.Marshal(withCandidates)
	if !bytes.Equal(legacyJSON, withCandidatesJSON) {
		t.Fatalf("opt-in candidates changed primary Result JSON\nlegacy: %s\nnew: %s", legacyJSON, withCandidatesJSON)
	}
	if len(candidateReport.Candidates) != 1 {
		t.Fatalf("got %d candidates, want only padded Base32", len(candidateReport.Candidates))
	}
	c := candidateReport.Candidates[0]
	if c.Encoding != "base32" || c.SyntaxValidity != "valid" || c.Identification != "unconfirmed" || !bytes.Equal(c.DecodedBytes, raw) {
		t.Fatalf("bad Base32 candidate: encoding=%s validity=%s identification=%s bytes=%d", c.Encoding, c.SyntaxValidity, c.Identification, len(c.DecodedBytes))
	}
	if c.Location != "resp:body" || c.Direction != "response" || c.MessageOrdinal != 1 || c.TokenLength != len(token) || c.TokenSHA256 == "" || c.FlowID == "" || c.ID == "" {
		t.Fatalf("candidate provenance incomplete: %+v", c)
	}
	if c.IdentificationNote != candidateIdentificationNote {
		t.Fatalf("candidate attribution reason missing: %q", c.IdentificationNote)
	}
}

func TestStrictBase58CandidateLeadingZerosAndPublishedVector(t *testing.T) {
	for _, tc := range []struct {
		text string
		want []byte
	}{
		{"2NEpo7TZRRrLZSi2U", []byte("Hello World!")},
		{"112", []byte{0, 0, 1}},
	} {
		got, ok := strictBase58Candidate(tc.text)
		if !ok || !bytes.Equal(got, tc.want) {
			t.Errorf("Base58 %q = %x, valid=%v; want %x", tc.text, got, ok, tc.want)
		}
	}
	values := candidateValues("112")
	if len(values) != 1 || values[0].encoding != "base58" || !bytes.Equal(values[0].decoded, []byte{0, 0, 1}) {
		t.Fatalf("leading-zero Base58 sidecar candidate = %+v", values)
	}
	for _, bad := range []string{"0", "O", "I", "l", "1O0", "not a base58 value"} {
		if _, ok := strictBase58Candidate(bad); ok {
			t.Errorf("invalid Bitcoin Base58 token %q accepted", bad)
		}
	}
}

func TestStrictBase32CandidateCanonicalVariants(t *testing.T) {
	raw := []byte{0, 1, 2, 3, 0xfe, 0xff}
	padded := base32.StdEncoding.EncodeToString(raw)
	unpadded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	lowerPadded := strings.ToLower(padded)
	lowerUnpadded := strings.ToLower(unpadded)
	for _, token := range []string{padded, unpadded, lowerPadded, lowerUnpadded} {
		got, ok := strictBase32Candidate(token)
		if !ok || !bytes.Equal(got, raw) {
			t.Errorf("canonical Base32 %q = %x, valid=%v", token, got, ok)
		}
	}
	bad := []string{"", "mY======", padded + "=", " " + padded, padded[:len(padded)-3] + "!" + padded[len(padded)-2:]}
	for _, token := range bad {
		if _, ok := strictBase32Candidate(token); ok {
			t.Errorf("noncanonical Base32 token %q accepted", token)
		}
	}
}

func FuzzStrictDecodeCandidates(f *testing.F) {
	for _, seed := range []string{
		"MY======", "2NEpo7TZRRrLZSi2U", "112", "", "not a token", strings.Repeat("1", 513),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, token string) {
		values := candidateValues(token)
		if len(values) > maxCandidateEncodings {
			t.Fatalf("candidate count %d exceeds limit", len(values))
		}
		for _, value := range values {
			if len(value.decoded) > maxCandidateDecodedBytes {
				t.Fatalf("decoded length %d exceeds limit", len(value.decoded))
			}
			if value.encoding != "base32" && value.encoding != "base58" {
				t.Fatalf("unexpected encoding label %q", value.encoding)
			}
		}
	})
}

func TestAmbiguousCandidatesStayUnconfirmedAndOrdered(t *testing.T) {
	// This alphabet and legal length are accepted by strict RFC 4648 Base32,
	// Bitcoin Base58, and the legacy Base64 run. No encoding is attributable.
	encodedToken := strings.Repeat("ABCDEFGHJKLMNPQRSTUVWXYZ234567", 8)
	primary, primaryEncoding, _, _ := decodeRespToken(encodedToken)
	if primaryEncoding != "base64" || len(primary) == 0 {
		t.Fatalf("legacy primary = %s/%d, want Base64", primaryEncoding, len(primary))
	}
	candidates := candidateValues(encodedToken)
	if len(candidates) != 2 || candidates[0].encoding != "base32" || candidates[1].encoding != "base58" {
		t.Fatalf("candidate order/content = %+v, want base32 then base58", candidates)
	}

	makeReport := func(input []token) []byte {
		e := &Engine{candidateCollector: newCandidateCollector()}
		ch := &httpChannel{key: httpChanKey{
			client: netip.MustParseAddr("10.0.0.1"), server: netip.MustParseAddr("10.0.0.2"), port: 80, host: "example.test",
		}, responses: 4}
		m := &httpMsg{frame: 77}
		e.collectCandidates(ch, m, input)
		sortDecodeCandidates(e.candidateCollector.report.Candidates)
		b, err := json.Marshal(e.candidateCollector.report)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	items := []token{{loc: "resp:body", val: encodedToken}, {loc: "resp:header:x-data", val: encodedToken}}
	a, b := makeReport(items), makeReport([]token{items[1], items[0]})
	if !bytes.Equal(a, b) {
		t.Fatalf("candidate order depends on token enumeration\n%s\n%s", a, b)
	}
	var report DecodeCandidateReport
	if err := json.Unmarshal(a, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Candidates) != 4 {
		t.Fatalf("got %d interpretations, want two encodings at each of two locations", len(report.Candidates))
	}
	for _, c := range report.Candidates {
		if c.Identification != "unconfirmed" || c.SyntaxValidity != "valid" || c.IdentificationNote == "" {
			t.Errorf("candidate was not explicitly unconfirmed: %+v", c)
		}
	}
}

func TestCandidateBoundsAndDisabledPath(t *testing.T) {
	long := strings.Repeat("1", maxCandidateTokenBytes+1)
	e := &Engine{candidateCollector: newCandidateCollector()}
	ch := &httpChannel{key: httpChanKey{client: netip.MustParseAddr("10.0.0.1"), server: netip.MustParseAddr("10.0.0.2"), port: 80}}
	e.collectCandidates(ch, &httpMsg{frame: 1}, []token{{loc: "resp:body", val: long}})
	if e.candidateCollector.report.Truncated.TokenTooLong != 1 || len(e.candidateCollector.report.Candidates) != 0 {
		t.Fatalf("oversized token was not bounded: %+v", e.candidateCollector.report.Truncated)
	}
	maxValue := candidateValues(strings.Repeat("1", maxCandidateTokenBytes))
	if len(maxValue) != 1 || len(maxValue[0].decoded) != maxCandidateDecodedBytes {
		t.Fatalf("maximum-size Base58 candidate escaped its bound: count=%d", len(maxValue))
	}

	e = &Engine{candidateCollector: newCandidateCollector()}
	ch = &httpChannel{key: httpChanKey{client: netip.MustParseAddr("10.0.0.1"), server: netip.MustParseAddr("10.0.0.2"), port: 80}}
	invalid := make([]token, maxCandidateAttemptsCapture+8)
	for i := range invalid {
		invalid[i] = token{loc: "resp:body", val: fmt.Sprintf("!%08d", i)}
	}
	e.collectCandidates(ch, &httpMsg{frame: 2}, invalid)
	if e.candidateCollector.attempts != maxCandidateAttemptsCapture || e.candidateCollector.report.Truncated.AttemptLimit != 8 {
		t.Fatalf("attempt cap accounting: attempts=%d truncation=%+v", e.candidateCollector.attempts, e.candidateCollector.report.Truncated)
	}

	e = &Engine{candidateCollector: newCandidateCollector()}
	ch = &httpChannel{key: httpChanKey{client: netip.MustParseAddr("10.0.0.1"), server: netip.MustParseAddr("10.0.0.2"), port: 80}}
	repeated := make([]token, maxCandidateRecordsChannel+1)
	for i := range repeated {
		repeated[i] = token{loc: "resp:body", val: base32.StdEncoding.EncodeToString([]byte{byte(i)})}
	}
	e.collectCandidates(ch, &httpMsg{frame: 3}, repeated)
	if len(e.candidateCollector.report.Candidates) != maxCandidateRecordsChannel || e.candidateCollector.report.Truncated.ChannelRecordCap != 1 {
		t.Fatalf("per-channel cap: records=%d truncation=%+v", len(e.candidateCollector.report.Candidates), e.candidateCollector.report.Truncated)
	}
	if maxCandidateRecordsChannel*maxCandidateDecodedBytes > maxCandidateBytesChannel || maxCandidateRecordsCapture*maxCandidateDecodedBytes > maxCandidateBytesCapture {
		t.Fatal("byte caps are smaller than the maximum record envelope")
	}

	// Cross-channel pressure reaches the capture record cap independently of
	// the per-channel cap; the next channel contributes deterministic truncation.
	e = &Engine{candidateCollector: newCandidateCollector()}
	for flow := 0; flow < maxCandidateRecordsCapture/maxCandidateRecordsChannel+1; flow++ {
		ch = &httpChannel{key: httpChanKey{
			client: netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", flow+1)),
			server: netip.MustParseAddr("10.0.1.1"), port: 80, host: "example.test",
		}, responses: 1}
		items := make([]token, maxCandidateRecordsChannel)
		for i := range items {
			items[i] = token{loc: "resp:body", val: base32.StdEncoding.EncodeToString([]byte{byte(i)})}
		}
		e.collectCandidates(ch, &httpMsg{frame: int64(flow + 1)}, items)
	}
	if got := len(e.candidateCollector.report.Candidates); got != maxCandidateRecordsCapture || e.candidateCollector.report.Truncated.RecordLimit != maxCandidateRecordsChannel {
		t.Fatalf("capture record cap: records=%d truncation=%+v", got, e.candidateCollector.report.Truncated)
	}

	// Candidate-disabled analysis is the existing API and has no candidate
	// side channel; it cannot add serialized fields or alter scoring.
	if e := New(Config{}); e.candidateCollector != nil {
		t.Fatal("default Engine unexpectedly enables candidate collection")
	}
}

func TestCandidatePrimaryEqualityAcrossTimingModes(t *testing.T) {
	raw := make([]byte, 31)
	for i := range raw {
		raw[i] = byte(17*i + 3)
	}
	token := base32.StdEncoding.EncodeToString(raw)
	path := candidateHTTPFile(t, token)
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		before, err := AnalyzeFile(path, cfg)
		if err != nil {
			t.Fatal(err)
		}
		after, candidates, err := AnalyzeFileWithCandidates(path, cfg)
		if err != nil {
			t.Fatal(err)
		}
		b1, _ := json.Marshal(before)
		b2, _ := json.Marshal(after)
		if !bytes.Equal(b1, b2) {
			t.Fatalf("candidate mode changed primary JSON for timingV2=%v", cfg.TimingV2)
		}
		if len(candidates.Candidates) == 0 {
			t.Fatalf("candidate sidecar empty for timingV2=%v", cfg.TimingV2)
		}
	}
}

func TestCandidateResponseBodyRequiresCompleteRetainedToken(t *testing.T) {
	raw := make([]byte, 500)
	for i := range raw {
		raw[i] = byte((i*71 + 19) % 256)
	}
	cases := []struct {
		name, body, codec string
	}{
		{"base32-over-head", base32.StdEncoding.EncodeToString(raw), "base32"},
		{"base58-over-head", strings.Repeat("z", 600), "base58"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.body) <= headSample {
				t.Fatalf("fixture is not over retained head: %d", len(tc.body))
			}
			path := candidateHTTPFile(t, tc.body)
			_, rep, err := AnalyzeFileWithCandidates(path, Config{})
			if err != nil {
				t.Fatal(err)
			}
			if rep.Truncated.IncompleteBody != 1 {
				t.Fatalf("incomplete body omission count=%d, want 1; counters=%+v", rep.Truncated.IncompleteBody, rep.Truncated)
			}
			if rep.SchemaVersion != candidateSchemaVersion {
				t.Fatalf("sidecar schema version=%d, want %d", rep.SchemaVersion, candidateSchemaVersion)
			}
			for _, c := range rep.Candidates {
				if c.Location == "resp:body" && c.Encoding == tc.codec {
					t.Fatalf("emitted candidate from incomplete %s body prefix: bytes=%d token_length=%d", tc.codec, len(c.DecodedBytes), c.TokenLength)
				}
			}
		})
	}

	// A body exactly equal to the retained bound is complete and remains
	// eligible when the parser observes its declared body terminator.
	for _, tc := range []struct {
		name, body, codec string
	}{
		{"base32-exact-head", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:320]), "base32"},
		{"base58-exact-head", strings.Repeat("1", headSample), "base58"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.body) != headSample {
				t.Fatalf("fixture length=%d, want %d", len(tc.body), headSample)
			}
			path := candidateHTTPFile(t, tc.body)
			_, rep, err := AnalyzeFileWithCandidates(path, Config{})
			if err != nil {
				t.Fatal(err)
			}
			if rep.Truncated.IncompleteBody != 0 {
				t.Fatalf("complete boundary body counted incomplete: %+v", rep.Truncated)
			}
			found := false
			for _, c := range rep.Candidates {
				if c.Location == "resp:body" && c.Encoding == tc.codec {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("complete %s token at exact retained boundary was omitted", tc.codec)
			}
		})
	}

	// A short body can still be incomplete because framing was truncated.
	e := &Engine{candidateCollector: newCandidateCollector()}
	ch := &httpChannel{key: httpChanKey{host: "incomplete.example"}}
	m := &httpMsg{frame: 7, bodyLen: 28, head: []byte("MZXW6YTBOIMZXW6YTBOIMZXW"), truncated: true}
	e.collectCandidates(ch, m, []token{{loc: "resp:body", val: string(m.head)}})
	if len(e.candidateCollector.report.Candidates) != 0 || e.candidateCollector.report.Truncated.IncompleteBody != 1 {
		t.Fatalf("truncated short body was not safely omitted: candidates=%d counters=%+v", len(e.candidateCollector.report.Candidates), e.candidateCollector.report.Truncated)
	}
}

func TestIncompleteResponseBodyDoesNotSuppressRequestCandidates(t *testing.T) {
	raw := make([]byte, 31)
	for i := range raw {
		raw[i] = byte(17*i + 3)
	}
	requestToken := base32.StdEncoding.EncodeToString(raw)
	s := newSynth(t)
	ts0 := s.now
	sess := s.tcp(ts0, "10.1.1.20", 52000, "203.0.113.77", 80)
	ts0 = sess.Send(ts0, true, sy.HTTPReq("GET", "/candidate?d="+requestToken, []string{"Host: candidate.example", "User-Agent: test"}, ""), 1400)
	ts0 = sess.Send(ts0.Add(time.Millisecond), false, sy.HTTPResp("HTTP/1.1 200 OK", []string{"Content-Type: text/plain"}, strings.Repeat("z", 600)), 1400)
	sess.Close(ts0.Add(time.Second))
	path := filepath.Join(t.TempDir(), "candidate.pcap")
	if err := os.WriteFile(path, s.buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	_, rep, err := AnalyzeFileWithCandidates(path, Config{})
	if err != nil {
		t.Fatal(err)
	}
	requestFound := false
	for _, c := range rep.Candidates {
		if c.Direction == "request" && c.Location == "query:d" && bytes.Equal(c.DecodedBytes, raw) {
			requestFound = true
		}
		if c.Direction == "response" && c.Location == "resp:body" {
			t.Fatalf("incomplete response body candidate emitted: %+v", c)
		}
	}
	if !requestFound || rep.Truncated.IncompleteBody == 0 {
		t.Fatalf("request candidate not preserved alongside omission: requestFound=%v counters=%+v", requestFound, rep.Truncated)
	}
}

func TestCandidateSuppressesBodyWithIncompleteHTTPFraming(t *testing.T) {
	for _, tc := range []struct {
		name, token string
	}{
		{"base32", "MZXW6YTBOIMZXW6YTBOIMZXW6Y"},
		{"base58", strings.Repeat("z", 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSynth(t)
			ts := s.now
			sess := s.tcp(ts, "10.1.1.20", 52000, "203.0.113.77", 80)
			ts = sess.Send(ts, true, sy.HTTPReq("GET", "/candidate", []string{"Host: candidate.example", "User-Agent: test"}, ""), 1400)
			response := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 200\r\n\r\n" + tc.token)
			ts = sess.Send(ts.Add(time.Millisecond), false, response, 1400)
			sess.Close(ts.Add(time.Second)) // closes before the declared body ends
			path := filepath.Join(t.TempDir(), "candidate.pcap")
			if err := os.WriteFile(path, s.buf.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			_, rep, err := AnalyzeFileWithCandidates(path, Config{})
			if err != nil {
				t.Fatal(err)
			}
			if rep.Truncated.IncompleteBody == 0 {
				t.Fatalf("incomplete framed body not counted: %+v", rep.Truncated)
			}
			for _, c := range rep.Candidates {
				if c.Direction == "response" && c.Location == "resp:body" {
					t.Fatalf("candidate emitted from incomplete framed body: %+v", c)
				}
			}
		})
	}
}

func TestCandidateRequestTokenStillUsesSizeBound(t *testing.T) {
	s := newSynth(t)
	ts := s.now
	sess := s.tcp(ts, "10.1.1.20", 52000, "203.0.113.77", 80)
	oversized := strings.Repeat("1", maxCandidateTokenBytes+1)
	ts = sess.Send(ts, true, sy.HTTPReq("GET", "/candidate?d="+oversized, []string{"Host: candidate.example", "User-Agent: test"}, ""), 1400)
	ts = sess.Send(ts.Add(time.Millisecond), false, sy.HTTPResp("HTTP/1.1 200 OK", []string{"Content-Type: text/plain"}, "ok"), 1400)
	sess.Close(ts.Add(time.Second))
	path := filepath.Join(t.TempDir(), "candidate.pcap")
	if err := os.WriteFile(path, s.buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	_, rep, err := AnalyzeFileWithCandidates(path, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Truncated.TokenTooLong == 0 {
		t.Fatalf("oversized request token was not counted: %+v", rep.Truncated)
	}
	for _, c := range rep.Candidates {
		if c.Direction == "request" && c.Location == "query:d" {
			t.Fatalf("oversized request token emitted as candidate: %+v", c)
		}
	}
}
