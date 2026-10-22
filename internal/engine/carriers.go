package engine

import (
	"encoding/base64"
	"encoding/hex"
	"hash/fnv"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"c2parser/internal/stats"
)

// Carrier analysis applies protocol-agnostic heuristics to selected HTTP URI,
// header, cookie and response fields and supported encodings. A match does not
// attribute traffic to a particular framework or profile. Each request token
// gets its established primary decode, and the *decoded* bytes are assessed.
// v11a COA 3 exposes separate, unconfirmed Base32/Base58 candidates through
// an opt-in sidecar; it does not replace the primary decode. Word runs and the
// response side (non-standard response headers and the retained response-body
// prefix) use the carrier analysis path.

type token struct {
	loc string // "path" | "query:<k>" | "query" | "cookie:<k>" | "header:<k>" | "resp:header:<k>" | "resp:body"
	val string
}

const minTokenLen = 16

// Request headers whose values are expected and not carriers.
var standardHeaders = map[string]bool{}

// Response headers whose values are expected, machine-generated or random
// by design and so can't be evidence: Set-Cookie session ids, ETags and
// the request/trace ids every CDN and cloud front end stamps on responses
// (fresh random per response on perfectly benign sites).
var respStandardHeaders = map[string]bool{}

// Response header prefixes of CDN / cloud / tracing ids (v11a N1 benign
// exclusions; random per response by design).
var respIDHeaderPrefixes = []string{"x-amz", "x-ms-", "x-goog", "x-guploader", "x-azure", "x-akamai", "akamai-",
	"cf-", "x-cache", "x-served", "x-timer", "x-trace", "x-request", "x-correlation", "x-b3-", "x-datadog",
	"x-envoy", "x-fb-", "x-github", "x-cdn", "x-backend", "x-origin", "x-varnish", "x-proxy", "x-runtime",
	"x-cloud-trace", "x-edge", "x-fastly", "x-iinfo", "x-hw", "x-content-", "x-frame", "x-xss", "x-litespeed",
	"x-nf-", "x-vercel", "x-netlify", "x-nginx", "x-upstream", "x-session", "x-csrf", "x-xsrf", "cross-origin-",
	"access-control-", "content-", "report-", "permissions-", "referrer-", "x-download-options", "x-permitted"}

func init() {
	for _, h := range strings.Fields(`host user-agent accept accept-language accept-encoding accept-charset connection
	content-type content-length content-encoding cache-control pragma cookie referer origin upgrade te dnt
	transfer-encoding keep-alive expect range if-modified-since if-none-match if-match if-range
	upgrade-insecure-requests authorization proxy-authorization proxy-connection x-requested-with
	sec-websocket-key sec-websocket-version sec-websocket-extensions sec-websocket-protocol priority`) {
		standardHeaders[h] = true
	}
	for _, h := range strings.Fields(`server date set-cookie location etag last-modified expires vary
	accept-ranges age via refresh www-authenticate proxy-authenticate retry-after link alt-svc nel
	server-timing timing-allow-origin traceparent tracestate request-id x-powered-by x-aspnet-version
	x-aspnetmvc-version strict-transport-security content-security-policy content-security-policy-report-only
	sec-websocket-accept digest content-md5 p3p`) {
		respStandardHeaders[h] = true
	}
}

func requestTokens(m *httpMsg) []token {
	var out []token
	uri := m.uri
	path, rawq, _ := strings.Cut(uri, "?")
	if i := strings.Index(path, "://"); i >= 0 { // absolute-form (proxy) request
		if j := strings.IndexByte(path[i+3:], '/'); j >= 0 {
			path = path[i+3+j:]
		}
	}
	for _, seg := range strings.Split(path, "/") {
		if len(seg) >= minTokenLen {
			out = append(out, token{"path", seg})
		}
	}
	if rawq != "" {
		vals, err := url.ParseQuery(rawq)
		if err != nil || len(vals) == 0 {
			if len(rawq) >= minTokenLen {
				out = append(out, token{"query", rawq})
			}
		}
		// url.ParseQuery returns a map; iterate keys in sorted order so token
		// order is deterministic (PM-4). Each key's value order is preserved.
		qkeys := make([]string, 0, len(vals))
		for k := range vals {
			qkeys = append(qkeys, k)
		}
		sort.Strings(qkeys)
		for _, k := range qkeys {
			for _, v := range vals[k] {
				if len(v) >= minTokenLen {
					out = append(out, token{"query:" + k, v})
				} else if v == "" && len(k) >= minTokenLen { // bare "?<token>"
					out = append(out, token{"query", k})
				}
			}
		}
	}
	for _, c := range strings.Split(m.hdr["cookie"], ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(c), "=")
		if ok && len(v) >= minTokenLen {
			out = append(out, token{"cookie:" + k, v})
		}
	}
	for _, name := range m.order {
		ln := strings.ToLower(name)
		if standardHeaders[ln] || strings.HasPrefix(ln, "sec-ch-") || strings.HasPrefix(ln, "sec-fetch-") {
			continue
		}
		if v := m.hdr[ln]; len(v) >= minTokenLen {
			out = append(out, token{"header:" + ln, v})
		}
	}
	return out
}

// unescapeRequestToken applies location-appropriate URL unescaping to a
// request carrier token before decoding (Q-07 / CAND2). Query values were
// already percent-decoded by url.ParseQuery in requestTokens, so they pass
// through unchanged — a second unescape would turn a standard-base64 '+' into
// a space and corrupt the token. Path, cookie and custom-header values are
// percent-decoded with url.PathUnescape, which decodes %XX escapes but, unlike
// QueryUnescape, leaves a literal '+' intact; the raw value is kept on any
// unescape error. This both stops the double-decode corruption of query tokens
// and recovers percent-encoded base64 carried in paths, cookies and headers.
func unescapeRequestToken(loc, v string) string {
	if loc == "query" || strings.HasPrefix(loc, "query:") {
		return v
	}
	if u, err := url.PathUnescape(v); err == nil {
		return u
	}
	return v
}

// isIDValue: hex digits and dashes only — UUIDs, traceparent, request ids.
func isIDValue(v string) bool {
	for i := 0; i < len(v); i++ {
		if c := v[i]; !(c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// responseTokens decomposes a response the way requestTokens decomposes a
// request (v11a N1): non-standard, non-id response headers, plus the body
// prefix http.go already retains (≤ headSample bytes; no whole body is
// kept). Opaque content types (images, fonts, archives …) are skipped.
// Ordinary web content needs no content-type rule: every decoder demands
// that the encoded run is most of the token, so an HTML/JS/JSON page whose
// head is markup with a nonce in it never decodes, and analyseCarriers
// only counts response tokens that actually decoded (raw binary bodies
// are random_payloads' evidence, not a carrier).
func responseTokens(m *httpMsg) []token {
	var out []token
	for _, name := range m.order {
		ln := strings.ToLower(name)
		if standardHeaders[ln] || respStandardHeaders[ln] ||
			strings.HasPrefix(ln, "sec-ch-") || strings.HasPrefix(ln, "sec-fetch-") {
			continue
		}
		skip := false
		for _, p := range respIDHeaderPrefixes {
			if strings.HasPrefix(ln, p) {
				skip = true
				break
			}
		}
		if v := m.hdr[ln]; !skip && len(v) >= minTokenLen && !isIDValue(v) {
			out = append(out, token{"resp:header:" + ln, v})
		}
	}
	if !benignOpaque(m.hdr["content-type"], m.hdr["content-encoding"]) {
		if body := strings.TrimSpace(string(m.head)); len(body) >= minTokenLen {
			out = append(out, token{"resp:body", body})
		}
	}
	return out
}

var b64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{24,}={0,2}`)

// decodeToken undoes common transform chains. It returns the decoded bytes
// and the name of the encoding, or the raw bytes with "raw".
func decodeToken(v string) ([]byte, string) {
	b, enc, _, _ := decodeTokenWrap(v)
	return b, enc
}

// decodeTokenWrap is decodeToken that also returns the constant wrapper
// (prepend/append) around the encoded run, for the evidence string.
//
// Per token the decoding is exactly v10's for every token v10 could
// decode (hex, netbios, base64/base64url run). v11a remediation F04:
// base32 and base58 alphabets are subsets of base64's, so a single token
// cannot say which it is — "Abc123XYZ789"×16 is valid base64 *and* valid
// base58 — and neither can a location (recovery audit). The v10 label
// stands, per token and per location. The only new per-token decoding is
// the word run, applied to tokens v10 left as "raw".
func decodeTokenWrap(v string) (b []byte, enc, pre, suf string) {
	if u, err := url.QueryUnescape(v); err == nil {
		v = u
	}
	return decodeUnescaped(v)
}

// decodeRespToken decodes a response token. Response headers and bodies
// are not URL-encoded, so they skip the query unescape — which would turn
// a standard-base64 '+' into a space (v10 applies it to every request
// token, cookies and headers included; kept there for byte-identical
// request findings, recorded in docs/review-v11a.md).
func decodeRespToken(v string) (b []byte, enc, pre, suf string) {
	return decodeUnescaped(v)
}

func decodeUnescaped(v string) (b []byte, enc, pre, suf string) {
	if len(v)%2 == 0 && isHexToken(v) {
		if b, err := hex.DecodeString(v); err == nil {
			return b, "hex", "", ""
		}
	}
	if b, ok := netbiosDecode(v); ok {
		return b, "netbios", "", ""
	}
	// Longest base64 run, so prepend/append wrappers don't break decoding.
	start, end := -1, -1
	for _, ix := range b64Run.FindAllStringIndex(v, 8) {
		if ix[1]-ix[0] > end-start {
			start, end = ix[0], ix[1]
		}
	}
	if start >= 0 && (end-start)*4 >= len(v)*3 { // the run is most of the token
		if b, enc := decodeB64(v[start:end]); b != nil {
			return b, enc, v[:start], v[end:]
		}
	}
	// v11a: tokens v10 left raw
	if b, ok := decodeWordRun(v); ok {
		return b, "english", "", ""
	}
	return []byte(v), "raw", "", ""
}

func isHexToken(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return len(s) > 0
}

func decodeB64(s string) ([]byte, string) {
	t := strings.TrimRight(s, "=")
	if strings.ContainsAny(t, "-_") {
		if b, err := base64.RawURLEncoding.DecodeString(t); err == nil {
			return b, "base64url"
		}
		return nil, ""
	}
	if b, err := base64.RawStdEncoding.DecodeString(t); err == nil {
		return b, "base64"
	}
	// lengths ≡ 1 mod 4 can't be valid; drop the last char and retry
	if len(t) > 4 {
		if b, err := base64.RawStdEncoding.DecodeString(t[:len(t)/4*4]); err == nil {
			return b, "base64"
		}
	}
	return nil, ""
}

// netbiosDecode reverses the a–p/A–P nibble transform: each byte becomes two
// letters, 'a'+high nibble and 'a'+low nibble. This transform alone does not
// identify a framework or profile.
func netbiosDecode(s string) ([]byte, bool) {
	if len(s) < 32 || len(s)%2 != 0 {
		return nil, false
	}
	base := byte('a')
	if s[0] >= 'A' && s[0] <= 'P' {
		base = 'A'
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		h, l := s[i]-base, s[i+1]-base
		if h > 15 || l > 15 {
			return nil, false
		}
		out[i/2] = h<<4 | l
	}
	return out, true
}

// ------------------------------------------------- v11a N1 encodings

// Bounds on word-run decoding.
const (
	minWords  = 24 // a word run shorter than this decodes to < 24 bytes, below the randomness gate
	maxWords  = 2048
	maxWordLn = 32
)

// v11a F04: the primary path preserves the v10 decoding (hex, netbios,
// base64/base64url run) and every location reports the same labels and
// primary fresh-random counts. Base32/Base58 alphabets overlap those primary
// alphabets, so an alternate decode is not proof of intended encoding. COA 3
// returns syntactically valid alternate interpretations only as explicitly
// unconfirmed sidecar candidates; they never enter primary scoring.

// Word runs (v11a remediation F03). Source-grounded on the supplied local
// Sliver snapshot (_reference-sources/sliver/util/encoders/english.go; ZIP
// provenance and commit identity unverified):
// Encode joins one dictionary word per byte with single spaces; Decode
// splits on " ", trims each word, skips empty ones and takes
// SumWord = (sum of the word's character values) mod 256 — case
// sensitive. Both shipped dictionaries contain only ASCII letters and
// every word has an uppercase letter, so letters of either case are
// accepted and *never* case-folded (folding would change the sum).
// Separators: whitespace only. The dictionary itself is not needed.

// wordState is the streaming word-run decoder (one token, or a response
// body fed fragment by fragment — the state carries across fragment
// boundaries, so splitting changes nothing).
//
// Separators follow the snapshot's Decode exactly: pieces are split on
// ' ' only, empty pieces are skipped, and each piece is TrimSpace'd, so
// tab / CR / LF may sit only at a word's edges. "Foo\nBar" is one piece
// to Sliver (its sum would include the 10 of '\n'); it is not a run of
// dictionary words, so it is rejected here (scope, not protocol, choice:
// the shipped dictionaries are ASCII letters only).
type wordState struct {
	sum, wl, words int
	closed         bool // the current piece's word ended in whitespace other than ' '
	bad            bool
}

// feed consumes b; onByte receives each completed word's byte.
func (w *wordState) feed(b []byte, onByte func(byte)) {
	for _, c := range b {
		if w.bad {
			return
		}
		switch {
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			if w.closed { // whitespace inside a ' '-delimited piece
				w.bad = true
				return
			}
			w.sum += int(c)
			w.wl++
			if w.wl > maxWordLn {
				w.bad = true
			}
		case c == ' ':
			w.flush(onByte)
			w.closed = false
		case c == '\t' || c == '\n' || c == '\r':
			if w.wl > 0 {
				w.closed = true // trimmed by TrimSpace: allowed only before the next ' '
			}
		default:
			w.bad = true
		}
	}
}

func (w *wordState) flush(onByte func(byte)) {
	if w.wl > 0 {
		w.words++
		if onByte != nil {
			onByte(byte(w.sum))
		}
		w.sum, w.wl = 0, 0
	}
}

// decodeWordRun decodes a whole word-run token (≥ minWords words; at most
// maxWords are decoded).
func decodeWordRun(v string) ([]byte, bool) {
	if len(v) < minWords*2 {
		return nil, false
	}
	out := make([]byte, 0, 64)
	var w wordState
	w.feed([]byte(v), func(c byte) {
		if len(out) < maxWords {
			out = append(out, c)
		}
	})
	w.flush(func(c byte) {
		if len(out) < maxWords {
			out = append(out, c)
		}
	})
	if w.bad || w.words < minWords {
		return nil, false
	}
	return out, true
}

// bodyWords is the bounded streaming word-run decoder for a response
// body: it sees every body byte (not only the 512-byte retained prefix)
// but keeps only a 256-bin histogram of the decoded bytes. It is
// allocated only when the body's first chunk looks like a word run.
type bodyWords struct {
	w    wordState
	hist stats.Histogram
}

func (bw *bodyWords) add(b []byte) {
	bw.w.feed(b, func(c byte) { bw.hist.Counts[c]++; bw.hist.N++ })
}

// result finalises the stream: the decoded-byte histogram, if the whole
// body was a word run of ≥ minWords words.
func (bw *bodyWords) result() (*stats.Histogram, bool) {
	bw.w.flush(func(c byte) { bw.hist.Counts[c]++; bw.hist.N++ })
	if bw.w.bad || bw.w.words < minWords {
		return nil, false
	}
	return &bw.hist, true
}

// Admission of a response body to the streamed word decoder (F03,
// recovery audit): decided on the body's first wordPrefixLen bytes,
// however they are fragmented. While fewer bytes have arrived and nothing
// disqualifies them the decision is pending; it is re-evaluated as each
// fragment arrives.
const wordPrefixLen = 64

type admission int

const (
	admitPending admission = iota
	admitYes
	admitNo
)

// wordPrefix: letters and whitespace only, with at least three word
// breaks within the first wordPrefixLen bytes.
func wordPrefix(head []byte) admission {
	n := min(len(head), wordPrefixLen)
	breaks := 0
	for i, c := range head[:n] {
		switch {
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if i > 0 {
				breaks++
			}
		default:
			return admitNo
		}
		if breaks >= 3 {
			return admitYes
		}
	}
	if n >= wordPrefixLen {
		return admitNo
	}
	return admitPending
}

// looksLikeWords: the first bytes, taken as the whole body so far, admit.
func looksLikeWords(b []byte) bool { return wordPrefix(b) == admitYes }

// isStructural (v11a remediation F02): the wrapper around a response-body
// run is document syntax — the run is a *field value* inside a JSON / XML /
// HTML document, not a bare encoded body.
func isStructural(pre, suf string) bool {
	return strings.ContainsAny(pre, "{}[]<>\"") || strings.ContainsAny(suf, "{}[]<>\"")
}

// ------------------------------------------------ Mythic-labeled heuristic

// This heuristic looks for a sufficiently long base64 run whose decoded bytes
// begin with an ASCII UUID-shaped prefix. In the inspected local Mythic source
// snapshot, agent-message parsing accepts both 36-byte textual and 16-byte
// binary UUID forms; this check recognizes only the textual form. A match is
// not a definitive Mythic signature, does not validate the remaining message,
// and does not establish a universal wire format or transport contract.
var uuidPrefix = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

func isMythicMessage(decoded []byte) bool {
	return len(decoded) >= 52 && uuidPrefix.Match(decoded[:36])
}

// mythicInText scans a buffer for base64 runs (≥ 72 chars ⇒ ≥ 54 bytes) whose
// decoding starts with a UUID. Returns the number of hits (max 8 checked).
func mythicInText(b []byte) int {
	hits := 0
	for i, r := range b64Run.FindAll(b, 8) {
		_ = i
		if len(r) < 72 {
			continue
		}
		// decode just enough to see the UUID (48 chars → 36 bytes)
		probe := strings.TrimRight(string(r), "=")
		if len(probe) > 96 {
			probe = probe[:96]
		}
		if d, _ := decodeB64(probe); d != nil && len(d) >= 52 && uuidPrefix.Match(d[:36]) {
			hits++
		}
	}
	return hits
}

// carrierStats aggregates tokens for one location within a channel.
type carrierStats struct {
	requests int // messages carrying this location (requests or responses)
	values   map[string]bool
	random   int
	mythic   int
	encs     map[string]int
	example  string
	resp     bool // a response location (v11a N1)
	// v11a remediation F02: fresh-random decoded runs that are field values
	// inside a structured response document; they count only when the
	// channel's requests carry encoded payload too.
	structRandom int
	// constant wrapper around the encoded run (v11a N1 evidence only)
	wrapN      int
	wrapPre    string
	wrapSuf    string
	wrapVaried bool
}

// noteWrapper records the prepend/append around one decoded token.
func (cs *carrierStats) noteWrapper(pre, suf string) {
	if len(pre) > 64 {
		pre = pre[:64]
	}
	if len(suf) > 64 {
		suf = suf[:64]
	}
	if cs.wrapN == 0 {
		cs.wrapPre, cs.wrapSuf = strings.Clone(pre), strings.Clone(suf)
	} else if pre != cs.wrapPre || suf != cs.wrapSuf {
		cs.wrapVaried = true
	}
	cs.wrapN++
}

// wrapperEvidence is the detail suffix naming a constant wrapper, or "".
func (cs *carrierStats) wrapperEvidence() string {
	if cs.wrapN < 2 || cs.wrapVaried || cs.wrapPre == "" && cs.wrapSuf == "" {
		return ""
	}
	out := ""
	if cs.wrapPre != "" {
		out += ", constant prefix " + quoteShort(cs.wrapPre)
	}
	if cs.wrapSuf != "" {
		out += ", constant suffix " + quoteShort(cs.wrapSuf)
	}
	return out
}

func quoteShort(s string) string {
	if len(s) > 32 {
		s = s[:32] + "…"
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// valueKey is the freshness key for a token value. Response bodies are
// keyed by a 64-bit hash so the per-location set stays small (≤ 5000 × 8
// bytes) however large the retained prefix; request tokens keep the v10
// string keys.
func valueKey(resp bool, v string) string {
	if !resp {
		return v
	}
	h := fnv.New64a()
	h.Write([]byte(v))
	return string(h.Sum(nil))
}
