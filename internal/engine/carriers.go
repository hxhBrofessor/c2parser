package engine

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"

	"c2parser/internal/stats"
)

// Payload carriers. Malleable C2 (Cobalt Strike profiles, Mythic httpx,
// Brute Ratel, Sliver HTTP) rarely puts data in a plain body. It hides it in
// the URI path, a query parameter, a cookie or a custom header, after a
// chain of transforms (base64, base64url, netbios, hex, prepend/append). So
// every request is decomposed into tokens, each token is decoded, and the
// *decoded* bytes are assessed.

type token struct {
	loc string // "path" | "query:<k>" | "cookie:<k>" | "header:<k>"
	val string
}

const minTokenLen = 16

// Request headers whose values are expected and not carriers.
var standardHeaders = map[string]bool{}

func init() {
	for _, h := range strings.Fields(`host user-agent accept accept-language accept-encoding accept-charset connection
	content-type content-length content-encoding cache-control pragma cookie referer origin upgrade te dnt
	transfer-encoding keep-alive expect range if-modified-since if-none-match if-match if-range
	upgrade-insecure-requests authorization proxy-authorization proxy-connection x-requested-with
	sec-websocket-key sec-websocket-version sec-websocket-extensions sec-websocket-protocol priority`) {
		standardHeaders[h] = true
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
		for k, vs := range vals {
			for _, v := range vs {
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

var b64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{24,}={0,2}`)

// decodeToken undoes common transform chains. It returns the decoded bytes
// and the name of the encoding, or the raw bytes with "raw".
func decodeToken(v string) ([]byte, string) {
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
	// Longest base64 run, so prepend/append wrappers don't break decoding.
	run := ""
	for _, r := range b64Run.FindAllString(v, 8) {
		if len(r) > len(run) {
			run = r
		}
	}
	if run != "" && len(run)*4 >= len(v)*3 { // the run is most of the token
		if b, enc := decodeB64(run); b != nil {
			return b, enc
		}
	}
	return []byte(v), "raw"
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

// netbiosDecode reverses Cobalt Strike / Mythic httpx "netbios" (a–p) and
// "netbiosu" (A–P): each byte becomes two letters, 'a'+high nibble,
// 'a'+low nibble.
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

// ------------------------------------------------- Mythic message signature

// Every Mythic agent message is base64( UUID(36 ASCII) ‖ IV ‖ ciphertext ‖
// HMAC ), whichever C2 profile carries it. The UUID survives encryption, so
// finding a base64 run that decodes to a UUID-shaped prefix identifies a
// Mythic agent regardless of transport (HTTP body/query/cookie/header,
// WebSocket JSON, SMB pipe, TCP P2P).
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

// tokenAssessment returns the randomness of a token's decoded bytes.
func tokenAssessment(v string) (stats.Assessment, string, []byte) {
	d, enc := decodeToken(v)
	return stats.AssessBytes(d), enc, d
}

// carrierStats aggregates tokens for one location within a channel.
type carrierStats struct {
	requests int
	values   map[string]bool
	random   int
	mythic   int
	encs     map[string]int
	example  string
}
