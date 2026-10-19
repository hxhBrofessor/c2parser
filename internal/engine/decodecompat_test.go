package engine

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	mrand "math/rand/v2"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"c2parser/internal/stats"
	sy "c2parser/internal/synth"
)

// v11a remediation F04 (recovery audit): channel-level differential
// oracle. Base32 and base58 alphabets are subsets of base64's, so no
// statistic over unmarked tokens identifies the encoding: values drawn
// from the base58 alphabet are also canonical standard base64. Policy
// (conservative, pending an owner decision on marked alternatives): every
// carrier location reports exactly the labels and fresh-random counts the
// v10 decoder gives its tokens. The oracle below recomputes them with the
// verbatim v10 decoder (decodeTokenV10) and v10's counting rule and
// compares them with the emitted evidence, for request locations of every
// kind and for response locations.

// v10Location replays v10's per-location counting over the token values
// one location saw, in order.
func v10Location(vals []string, unescape bool) (map[string]int, int) {
	encs, random := map[string]int{}, 0
	seen := map[string]bool{}
	for _, v := range vals {
		fresh := !seen[v]
		seen[v] = true
		var d []byte
		var enc string
		if unescape {
			d, enc = decodeTokenV10(v)
		} else { // response tokens: same v10 decoder, no query unescape
			d, enc = decodeTokenV10NoUnescape(v)
		}
		encs[enc]++
		if a := stats.AssessBytes(d); fresh && a.Score >= 0.8 && a.N >= 24 && (unescape || enc != "raw") {
			random++
		}
	}
	return encs, random
}

// decodeTokenV10NoUnescape is decodeTokenV10 minus the query unescape.
func decodeTokenV10NoUnescape(v string) ([]byte, string) {
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

// canonicalB64FromB58 draws 4·⌊L/4⌋ symbols from the Bitcoin base58
// alphabet (recovery-audit recipe): canonical standard base64 that is
// also a valid base58 string.
func canonicalB64FromB58(r *mrand.Rand, n int) string {
	const a = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	var b strings.Builder
	for i := 0; i < n/4*4; i++ {
		b.WriteByte(a[r.IntN(len(a))])
	}
	s := b.String()
	if d, err := base64.StdEncoding.DecodeString(s); err != nil || base64.StdEncoding.EncodeToString(d) != s {
		panic("not canonical base64")
	}
	return s
}

func TestCarrierChannelV10Compatibility(t *testing.T) {
	gens := map[string]func(r *mrand.Rand) string{
		"canonical base64 over the base58 alphabet": func(r *mrand.Rand) string { return canonicalB64FromB58(r, 280) },
		"bitcoin base58 of random bytes":            func(r *mrand.Rand) string { return sy.Base58(rbytes(r, 200)) },
		"unpadded base32 upper":                     func(r *mrand.Rand) string { return b32NoPad.EncodeToString(rbytes(r, 200)) },
		"unpadded base32 lower":                     func(r *mrand.Rand) string { return strings.ToLower(b32NoPad.EncodeToString(rbytes(r, 200))) },
		"base64url":                                 func(r *mrand.Rand) string { return base64.RawURLEncoding.EncodeToString(rbytes(r, 200)) },
		"hex":                                       func(r *mrand.Rand) string { return hex.EncodeToString(rbytes(r, 150)) },
		"netbios":                                   func(r *mrand.Rand) string { return netbiosOf(rbytes(r, 150)) },
		"static canonical base64":                   func(r *mrand.Rand) string { return canonicalB64FromB58(mrand.New(mrand.NewPCG(1, 1)), 280) },
	}
	type place struct {
		name, sig, loc string
		unescape       bool
		mk             func(v string) carrierMsg
	}
	places := []place{
		{"path", "encoded_payload_in_path", "path", true, func(v string) carrierMsg { return carrierMsg{uri: "/x/" + v} }},
		{"query", "encoded_payload_in_query", "query:d", true, func(v string) carrierMsg { return carrierMsg{uri: "/?d=" + url.QueryEscape(v)} }},
		{"cookie", "encoded_payload_in_cookie", "cookie:s", true, func(v string) carrierMsg { return carrierMsg{reqHdrs: []string{"Cookie: s=" + v}} }},
		{"header", "encoded_payload_in_header", "header:x-data", true, func(v string) carrierMsg { return carrierMsg{reqHdrs: []string{"X-Data: " + v}} }},
		{"response header", "encoded_payload_in_resp", "resp:header:x-data", false, func(v string) carrierMsg {
			return carrierMsg{respHdrs: []string{"Content-Type: text/plain", "X-Data: " + v}, body: "ok"}
		}},
		{"response body", "encoded_payload_in_resp", "resp:body", false, func(v string) carrierMsg { return carrierMsg{body: v} }},
	}
	names := make([]string, 0, len(gens))
	for n := range gens {
		names = append(names, n)
	}
	sortStrings(names)
	for _, gn := range names {
		for _, p := range places {
			r := seeded(4117, uint64(len(gn)))
			vals := make([]string, 12)
			for i := range vals {
				vals[i] = gens[gn](r)
			}
			tokVals := vals
			if p.name == "response header" { // N1 benign exclusion: hex/dash ID values are not response tokens
				tokVals = nil
				for _, v := range vals {
					if !isIDValue(v) {
						tokVals = append(tokVals, v)
					}
				}
			}
			encs, random := v10Location(tokVals, p.unescape)
			// 1. exact state: the location's label counts and fresh-random
			// count, through the real HTTP parser
			gotEncs, gotRandom, present := carrierState(t, 12, func(i int) carrierMsg { return p.mk(vals[i]) }, p.loc)
			if len(tokVals) > 0 && (!present || fmtCounts(gotEncs, 9) != fmtCounts(encs, 9) || gotRandom != random) {
				t.Errorf("%s in %s: state %s random %d (present %v), v10 %s random %d", gn, p.name,
					fmtCounts(gotEncs, 9), gotRandom, present, fmtCounts(encs, 9), random)
			}
			// 2. end to end: the emitted evidence, where v10's rules would
			// show it (signal contribution ≥ 0.05; findings below 0.05 are
			// not output — v10 behaviour)
			_, d := carrierSignal(carrierChannel(t, 12, func(i int) carrierMsg { return p.mk(vals[i]) }), p.sig)
			want := ""
			if 0.55*float64(random)/12 < 0.05 {
				continue
			}
			if random > 0 {
				want = fmt.Sprintf("%s: %d/12 %s carry a fresh, random-after-decoding token (%s)", p.loc, random,
					map[bool]string{true: "requests", false: "responses"}[p.unescape], fmtCounts(encs, 3))
			}
			if want == "" && d != "" || want != "" && !strings.HasPrefix(d, want) {
				t.Errorf("%s in %s:\n  got  %q\n  want %q (v10 decoder)", gn, p.name, d, want)
			}
		}
	}
}

func netbiosOf(b []byte) string {
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, 'a'+c>>4, 'a'+c&0x0f)
	}
	return string(out)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// carrierState feeds n request/response pairs through the HTTP parser of
// a fresh engine and returns one location's carrier state.
func carrierState(t *testing.T, n int, mk func(i int) carrierMsg, loc string) (map[string]int, int, bool) {
	t.Helper()
	e := New(Config{})
	c := &tcpConn{ch: &channel{}, client: netip.MustParseAddrPort("10.1.1.20:52000"), server: netip.MustParseAddrPort("203.0.113.77:80")}
	cli, srv := newHTTPHalf(e, c, true), newHTTPHalf(e, c, false)
	ts := time.Date(2024, 3, 25, 12, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		m := mk(i)
		uri := m.uri
		if uri == "" {
			uri = "/"
		}
		rh := m.respHdrs
		if rh == nil {
			rh = []string{"Content-Type: application/octet-stream"}
		}
		cli.feed(sy.HTTPReq("GET", uri, append([]string{"Host: carrier.example", "User-Agent: test/1.0"}, m.reqHdrs...), ""), ts, int64(2*i+1))
		srv.feed(sy.HTTPResp("HTTP/1.1 200 OK", rh, m.body), ts.Add(time.Millisecond), int64(2*i+2))
		ts = ts.Add(10 * time.Second)
	}
	for _, ch := range e.httpOrder {
		if cs := ch.carriers[loc]; cs != nil {
			return cs.encs, cs.random, true
		}
	}
	return nil, 0, false
}
