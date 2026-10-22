package engine

import (
	"bytes"
	"encoding/base64"
	"math/rand/v2"
	"strings"
	"testing"
)

// Q-07 / CAND2 decodeCarrier-level contract: for a request carrier token, the
// *decoded bytes* (decoded.b) must equal the original payload. This is the
// strong form of the earlier enc!=raw check — a token corrupted by a stray
// second unescape still often decodes to *some* base64, so only asserting the
// recovered bytes distinguishes correct from corrupted decoding.
//
// The test references only decodeCarrier (present pre- and post-Q-07), so it
// can be applied verbatim to the pre-Q-07 tree to prove discrimination.

// q07Payload returns a deterministic random payload of n(>=64) bytes whose
// StdEncoding form contains at least one '+' and one '/'.
func q07Payload(n int) (p []byte, std string) {
	r := rand.New(rand.NewPCG(0xC0FFEE, 0x0701))
	for {
		p = make([]byte, n)
		for i := range p {
			p[i] = byte(r.IntN(256))
		}
		std = base64.StdEncoding.EncodeToString(p)
		if strings.ContainsRune(std, '+') && strings.ContainsRune(std, '/') {
			return p, std
		}
	}
}

func q07Pct(std string) string {
	return strings.NewReplacer("+", "%2B", "/", "%2F", "=", "%3D").Replace(std)
}

func q07Decode(loc, val string) decoded {
	return decodeCarrier(&httpMsg{req: true}, token{loc: loc, val: val})
}

func TestQ07DecodedBytesByLocation(t *testing.T) {
	payload, std := q07Payload(66) // >= 64 bytes, '+' and '/' present
	pct := q07Pct(std)
	cases := []struct {
		name, loc, val string
		want           []byte // decoded.b must equal this
		discriminates  bool   // expected to FAIL on pre-Q-07 production
	}{
		{"raw+_cookie", "cookie:sid", std, payload, true},
		{"raw+_header", "header:x-session-data", std, payload, true},
		{"raw+_path", "path", std, payload, true},
		{"pct_cookie", "cookie:sid", pct, payload, false},
		{"pct_header", "header:x-session-data", pct, payload, false},
		{"pct_path", "path", pct, payload, false},
		// query value as delivered by url.ParseQuery (already decoded → literal '+'):
		{"query_asdelivered", "query:d", std, payload, true},
	}
	for _, c := range cases {
		got := q07Decode(c.loc, c.val)
		if !bytes.Equal(got.b, c.want) {
			t.Errorf("%s: decoded.b != payload (enc=%q, got %d bytes, want %d)",
				c.name, got.enc, len(got.b), len(c.want))
		}
	}
}

// Malformed percent-escape: unescape must fail closed to the raw value, so the
// token decodes exactly as the raw (non-base64) bytes rather than panicking or
// silently dropping it.
func TestQ07MalformedEscapeRawFallback(t *testing.T) {
	for _, loc := range []string{"cookie:sid", "header:x-data", "path"} {
		val := "short%ZZvalue!!" // invalid %-escape, not base64
		got := q07Decode(loc, val)
		if got.enc != "raw" || !bytes.Equal(got.b, []byte(val)) {
			t.Errorf("%s: malformed escape not kept raw (enc=%q, b=%q)", loc, got.enc, string(got.b))
		}
	}
}
