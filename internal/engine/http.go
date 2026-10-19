package engine

import (
	"bytes"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"c2parser/internal/stats"
)

// ---------------------------------------------------------------- parser
//
// An incremental HTTP/1.x parser fed with reassembled TCP bytes, one per
// direction. It never needs the whole message in memory: bodies are
// streamed into a byte histogram, and only the first 512 bytes are kept for
// signature matching. Handles Content-Length, chunked encoding,
// read-until-close, HEAD/1xx/204/304, pipelining and capture gaps.

const (
	stHead = iota
	stBody
	stChunkSize
	stChunkData
	stChunkEnd
	stTrailer
	stUntilClose
	stResync
	stTunnel // after a successful CONNECT: opaque bytes, stop parsing
	stWS     // after 101 + Upgrade: websocket
)

const (
	maxHeaderBytes = 64 << 10
	headSample     = 512
)

type httpMsg struct {
	req       bool
	ts        time.Time
	frame     int64
	method    string
	uri       string
	proto     string
	status    int
	hdr       map[string]string
	order     []string
	serverRaw string // Server value with trailing whitespace kept (PoshC2 sends "Apache ")
	bodyLen   int64
	hist      stats.Histogram
	head      []byte
	words     *bodyWords // v11a F03: streamed word-run decoding of a response body
	wordsDone bool       // v11a F03: admission decided (words set, or rejected)
	chunked   bool
	truncated bool
}

func (m *httpMsg) addBody(b []byte) {
	prev := m.bodyLen
	m.bodyLen += int64(len(b))
	m.hist.Add(b)
	if room := headSample - len(m.head); room > 0 {
		if room > len(b) {
			room = len(b)
		}
		m.head = append(m.head, b[:room]...)
	}
	if m.req || len(b) == 0 || !streamBodyWords {
		return
	}
	// v11a remediation F03: bounded streaming word-run decoder for
	// response bodies. Admission looks at the first wordPrefixLen body
	// bytes whatever the TCP segment / chunk boundaries: while pending,
	// every earlier body byte is still in m.head (prev < wordPrefixLen ≤
	// headSample), so on admission they are replayed exactly once, then
	// this fragment. Nothing beyond the retained head is ever buffered.
	switch {
	case m.words != nil:
		m.words.add(b)
	case !m.wordsDone:
		switch wordPrefix(m.head) {
		case admitYes:
			m.words = &bodyWords{}
			m.words.add(m.head[:prev])
			m.words.add(b)
			m.wordsDone = true
		case admitNo:
			m.wordsDone = true
		}
	}
}

type httpHalf struct {
	e      *Engine
	c      *tcpConn
	client bool
	buf    []byte
	st     int
	rem    int64
	msg    *httpMsg
	parsed int
	ws     *wsParser
}

func newHTTPHalf(e *Engine, c *tcpConn, client bool) *httpHalf {
	return &httpHalf{e: e, c: c, client: client}
}

var httpMethods = []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
	"PROPFIND ", "PROPPATCH ", "MKCOL ", "COPY ", "MOVE ", "LOCK ", "UNLOCK ", "SEARCH ", "M-SEARCH ", "NOTIFY ", "SUBSCRIBE "}

func looksLikeRequest(b []byte) bool {
	for _, m := range httpMethods {
		if len(b) >= len(m) {
			if bytes.HasPrefix(b, []byte(m)) {
				return true
			}
		} else if bytes.HasPrefix([]byte(m), b) {
			return true // not enough bytes yet; give it the benefit of the doubt
		}
	}
	return false
}

func looksLikeResponse(b []byte) bool {
	p := []byte("HTTP/1.")
	if len(b) < len(p) {
		return bytes.HasPrefix(p, b)
	}
	return bytes.HasPrefix(b, p)
}

func (h *httpHalf) looksLikeStart(b []byte) bool {
	if h.client {
		return looksLikeRequest(b)
	}
	return looksLikeResponse(b)
}

func (h *httpHalf) gap() {
	if h.msg != nil {
		h.msg.truncated = true
		h.finish()
	}
	h.buf = h.buf[:0]
	h.st = stResync
}

func (h *httpHalf) close(time.Time) {
	if h.msg != nil {
		if h.st != stUntilClose {
			h.msg.truncated = true
		}
		h.finish()
	}
}

func (h *httpHalf) feed(data []byte, ts time.Time, frame int64) {
	if h.c.tunnel || h.st == stTunnel {
		h.st, h.buf = stTunnel, nil
		h.e.tunnelData(h.c, h.client, data, ts, frame)
		return
	}
	if h.c.websocket && (h.st == stHead || h.st == stWS) {
		if h.ws == nil {
			h.ws = &wsParser{}
			data = append(h.buf, data...) // bytes buffered before the switch
			h.buf = nil
		}
		h.st = stWS
		h.ws.feed(h.e, h.c, h.client, data, ts, frame)
		return
	}
	h.buf = append(h.buf, data...)
	for {
		switch h.st {
		case stHead:
			if len(h.buf) == 0 {
				return
			}
			if !h.looksLikeStart(h.buf) {
				h.st = stResync
				continue
			}
			// Earliest terminator wins: an LF-only header block can be
			// followed by a body that happens to contain CRLFCRLF.
			end, sep := bytes.Index(h.buf, []byte("\r\n\r\n")), 4
			if e2 := bytes.Index(h.buf, []byte("\n\n")); e2 >= 0 && (end < 0 || e2 < end) {
				end, sep = e2, 2
			}
			if end < 0 {
				if len(h.buf) > maxHeaderBytes {
					h.st = stResync
					h.buf = h.buf[1:]
					continue
				}
				return
			}
			orig := h.buf
			h.buf = orig[end+sep:] // advance first: parseHead may switch state
			if !h.parseHead(orig[:end], ts, frame) {
				h.buf = orig[1:]
				h.st = stResync
				continue
			}
		case stBody, stChunkData:
			if len(h.buf) == 0 {
				return
			}
			n := int64(len(h.buf))
			if n > h.rem {
				n = h.rem
			}
			h.msg.addBody(h.buf[:n])
			h.buf = h.buf[n:]
			h.rem -= n
			if h.rem > 0 {
				return
			}
			if h.st == stBody {
				h.finish()
			} else {
				h.st = stChunkEnd
			}
		case stChunkEnd:
			if len(h.buf) == 0 {
				return
			}
			if h.buf[0] == '\n' {
				h.buf = h.buf[1:]
			} else if h.buf[0] == '\r' {
				if len(h.buf) < 2 {
					return
				}
				h.buf = h.buf[2:]
			}
			h.st = stChunkSize
		case stChunkSize:
			i := bytes.IndexByte(h.buf, '\n')
			if i < 0 {
				if len(h.buf) > 1024 {
					h.gap()
				}
				return
			}
			line := strings.TrimSpace(string(h.buf[:i]))
			if j := strings.IndexByte(line, ';'); j >= 0 {
				line = line[:j]
			}
			h.buf = h.buf[i+1:]
			size, err := strconv.ParseInt(strings.TrimSpace(line), 16, 64)
			if err != nil || size < 0 {
				h.gap()
				return
			}
			if size == 0 {
				h.st = stTrailer
			} else {
				h.rem, h.st = size, stChunkData
			}
		case stTrailer:
			i := bytes.IndexByte(h.buf, '\n')
			if i < 0 {
				if len(h.buf) > maxHeaderBytes {
					h.gap()
				}
				return
			}
			line := bytes.TrimRight(h.buf[:i], "\r")
			h.buf = h.buf[i+1:]
			if len(line) == 0 {
				h.finish()
			}
		case stUntilClose:
			if len(h.buf) > 0 {
				h.msg.addBody(h.buf)
			}
			h.buf = h.buf[:0]
			return
		case stTunnel, stWS:
			h.buf = nil
			return
		case stResync:
			j := h.findStart()
			if j < 0 {
				if len(h.buf) > resyncTail {
					h.buf = append(h.buf[:0], h.buf[len(h.buf)-resyncTail:]...)
				}
				return
			}
			h.buf = h.buf[j:]
			h.st = stHead
		}
	}
}

// Resync patterns (v9 Phase 1.4). After a TCP gap the next message can
// start anywhere — a request line follows the previous body directly, and
// binary bodies rarely end in a newline — so resync looks for a complete,
// valid request/status line at any offset, not only at line boundaries.
var (
	reqLineRe  = regexp.MustCompile(`(?:GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH|CONNECT|TRACE|PROPFIND|MKCOL|COPY|MOVE|LOCK|UNLOCK|SEARCH|REPORT|BITS_POST) [!-~]+ HTTP/1\.[01]\r?\n`)
	respLineRe = regexp.MustCompile(`HTTP/1\.[01] [1-5][0-9][0-9](?: [^\r\n]{0,256})?\r?\n`)
)

// resyncTail is how much of an unmatched buffer is kept: enough for a
// request line split across segments.
const resyncTail = 512

// findStart returns the offset of the next complete request (client) or
// status (server) line, or -1.
func (h *httpHalf) findStart() int {
	re := respLineRe
	if h.client {
		re = reqLineRe
	}
	if loc := re.FindIndex(h.buf); loc != nil {
		return loc[0]
	}
	return -1
}

func (h *httpHalf) parseHead(block []byte, ts time.Time, frame int64) bool {
	lines := strings.Split(string(block), "\n")
	start := strings.TrimRight(lines[0], "\r")
	m := &httpMsg{req: h.client, ts: ts, frame: frame, hdr: map[string]string{}}
	if h.client {
		parts := strings.SplitN(start, " ", 3)
		if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/") {
			return false
		}
		m.method, m.uri, m.proto = parts[0], parts[1], parts[2]
	} else {
		parts := strings.SplitN(start, " ", 3)
		if len(parts) < 2 {
			return false
		}
		code, err := strconv.Atoi(parts[1])
		if err != nil {
			return false
		}
		m.proto, m.status = parts[0], code
	}
	for _, l := range lines[1:] {
		l = strings.TrimRight(l, "\r")
		i := strings.IndexByte(l, ':')
		if i <= 0 {
			continue
		}
		k := strings.TrimSpace(l[:i])
		v := strings.TrimSpace(l[i+1:])
		lk := strings.ToLower(k)
		m.order = append(m.order, k)
		if _, dup := m.hdr[lk]; !dup {
			m.hdr[lk] = v
			if lk == "server" {
				m.serverRaw = strings.TrimLeft(l[i+1:], " \t")
			}
		}
	}
	h.msg = m
	h.parsed++

	chunked := strings.Contains(strings.ToLower(m.hdr["transfer-encoding"]), "chunked")
	cl, hasCL := int64(0), false
	if v, ok := m.hdr["content-length"]; ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			cl, hasCL = n, true
		}
	}
	m.chunked = chunked
	if h.client {
		h.c.pendingMethods = append(h.c.pendingMethods, m.method)
		if host := m.hdr["host"]; host != "" {
			h.c.lastHost = host
		}
		if strings.EqualFold(m.hdr["upgrade"], "websocket") && wsPushHeader(m.hdr["accept-type"]) {
			h.c.wsPush = true
		}
		if m.method == "CONNECT" {
			h.c.connectTarget = m.uri
		}
		switch {
		case chunked:
			h.st = stChunkSize
		case cl > 0:
			h.st, h.rem = stBody, cl
		default:
			h.finish()
		}
		return true
	}
	method := ""
	if m.status >= 200 && len(h.c.pendingMethods) > 0 {
		method = h.c.pendingMethods[0]
		h.c.pendingMethods = h.c.pendingMethods[1:]
	}
	switch {
	case m.status == 101 && strings.EqualFold(m.hdr["upgrade"], "websocket"):
		h.finish()
		h.c.websocket = true
		rest := h.buf
		h.buf = nil
		h.st = stWS
		h.ws = &wsParser{}
		if len(rest) > 0 {
			h.ws.feed(h.e, h.c, false, rest, ts, frame)
		}
	case method == "CONNECT" && m.status >= 200 && m.status < 300:
		h.finish()
		h.c.tunnel = true // everything after this is TLS (or anything) inside the tunnel
		rest := h.buf
		h.st, h.buf = stTunnel, nil
		h.e.openTunnel(h.c)
		if len(rest) > 0 {
			h.e.tunnelData(h.c, false, rest, ts, frame)
		}
	case m.status < 200 || m.status == 204 || m.status == 304 || method == "HEAD":
		h.finish()
	case chunked:
		h.st = stChunkSize
	case hasCL && cl > 0:
		h.st, h.rem = stBody, cl
	case hasCL:
		h.finish()
	default:
		h.st = stUntilClose
	}
	return true
}

func (h *httpHalf) finish() {
	m := h.msg
	h.msg = nil
	h.st = stHead
	if m != nil {
		h.e.onHTTPMessage(h.c, m)
	}
}

// --------------------------------------------------------------- analysis

type httpChanKey struct {
	client, server netip.Addr
	port           uint16
	host           string
}

// NotableMessage is an individual HTTP message worth looking at in Wireshark.
type NotableMessage struct {
	Frame     int64    `json:"frame"`
	Time      string   `json:"time"`
	Direction string   `json:"direction"`
	Line      string   `json:"line"`
	BodyBytes int64    `json:"body_bytes"`
	Alphabet  string   `json:"alphabet"`
	Shannon   float64  `json:"shannon"`
	Random    float64  `json:"randomness"`
	Sigs      []string `json:"signatures,omitempty"`
	CType     string   `json:"content_type,omitempty"`
}

type httpChannel struct {
	key                 httpChanKey
	requests, responses int
	reqT, reqSize       []float64
	upload, download    int64
	randomUp, randomDn  int
	randomUpBytes       int64
	randomDnBytes       int64
	legacyHits          int
	bigUploadSizes      []float64
	methods, uas, ctype counts
	uris                counts // first 64 distinct URIs
	sigHits             map[string]int
	sigWeight           map[string]float64
	fw                  map[string]*fwState // framework default-profile features seen
	anomalies           map[string]int
	anomalyDetail       map[string]string
	keepAlive           int
	fileUploads         []fileUpload
	ws                  *wsStats
	carriers            map[string]*carrierStats
	reqCarriers         int            // request locations in carriers (budget maxReqCarriers)
	respCarriers        int            // response locations in carriers (budget maxRespCarriers)
	candidateRecords    int            // opt-in decode-candidate sidecar budget
	candidateBytes      int            // opt-in decoded-byte budget
	shapes              *uriShapeStats // v11a N2, allocated on first shape hit
	residue             *residuePair   // v11a M2, allocated at the second eligible message
	residueFirst        residueFirst   // v11a F06: first eligible length per direction
	respAnoms           map[string]int
	respAnomDetail      map[string]string
	notable             []NotableMessage
	first, last         time.Time
	firstFrame          int64
	maxRandom           stats.Assessment
}

func (e *Engine) httpChan(c *tcpConn, host string) *httpChannel {
	if host == "" {
		host = c.server.Addr().String()
	}
	k := httpChanKey{c.client.Addr(), c.server.Addr(), c.server.Port(), strings.ToLower(host)}
	ch := e.httpChans[k]
	if ch == nil {
		k.host = strings.Clone(k.host) // don't pin the whole header block
		// Maps that most channels never write are allocated on first use
		// (v9c 3.3: one-shot channels dominate flow-heavy captures).
		ch = &httpChannel{key: k}
		e.httpChans[k] = ch
		e.httpOrder = append(e.httpOrder, ch)
	}
	return ch
}

// benignOpaque are content types that are *supposed* to be high entropy;
// randomness in them is not evidence of anything.
func benignOpaque(ctype, cenc string) bool {
	ct := strings.ToLower(ctype)
	if cenc != "" && !strings.EqualFold(cenc, "identity") {
		return true
	}
	for _, p := range []string{"image/", "video/", "audio/", "font/", "application/zip", "application/gzip",
		"application/x-gzip", "application/x-7z", "application/x-rar", "application/pkix", "application/x-x509",
		"application/pkcs7", "application/x-pkcs7", "application/ocsp", "application/x-chrome-extension",
		"application/vnd.ms-cab-compressed", "application/pdf", "application/wasm", "application/x-protobuf",
		"application/vnd.microsoft.portable-executable", "application/x-msdownload", "application/x-shockwave"} {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	return false
}

func (e *Engine) onHTTPMessage(c *tcpConn, m *httpMsg) {
	e.counters.HTTPMessages++
	host := m.hdr["host"]
	if !m.req {
		host = c.lastHost
	}
	ch := e.httpChan(c, host)
	if ch.first.IsZero() || m.ts.Before(ch.first) {
		ch.first, ch.firstFrame = m.ts, m.frame
	}
	if m.ts.After(ch.last) {
		ch.last = m.ts
	}
	if hn := strings.Trim(strings.Split(host, ":")[0], "[]"); hn != "" {
		if _, err := netip.ParseAddr(hn); err != nil { // skip IP-literal Hosts
			e.addName(c.server.Addr(), hn)
		}
	}

	a := stats.Assess(&m.hist)
	sigs := matchSignatures(m.head)
	ctype := m.hdr["content-type"]
	opaque := benignOpaque(ctype, m.hdr["content-encoding"])
	random := a.Score >= 0.8 && a.N >= 64 && !opaque
	if a.Shannon >= e.cfg.LegacyEntropy && a.N > 0 {
		ch.legacyHits++
	}
	if ctype != "" {
		ch.ctype.inc(ctype)
	}
	if strings.EqualFold(m.hdr["connection"], "keep-alive") {
		ch.keepAlive++
	}

	if m.req {
		ch.requests++
		if e.room(len(ch.reqT)) {
			ch.reqT = append(ch.reqT, e.rel(m.ts))
			ch.reqSize = append(ch.reqSize, float64(m.bodyLen))
		}
		ch.upload += m.bodyLen
		ch.methods.inc(m.method)
		if ch.uris.len() < 64 || ch.uris.get(m.uri) > 0 {
			ch.uris.inc(m.uri)
		}
		if ua := m.hdr["user-agent"]; ua != "" {
			ch.uas.inc(ua)
			hb := e.hostBaseline(c.client.Addr())
			incr(hb.ua, ua)
			dst := uaDest{c.server, ch.key.host}
			if u := hb.uaChans[ua]; u == nil {
				hb.uaChans[strings.Clone(ua)] = &uaDests{first: dst}
			} else if !u.multi && u.first != dst {
				u.multi = true
			}
		}
		if random {
			ch.randomUp++
			ch.randomUpBytes += m.bodyLen
		}
		if up, ok := detectUpload(m); ok && len(ch.fileUploads) < 50 {
			ch.fileUploads = append(ch.fileUploads, up)
		}
		if m.bodyLen >= 64<<10 {
			ch.bigUploadSizes = append(ch.bigUploadSizes, float64(m.bodyLen))
		}
		for _, an := range e.requestAnomalies(m) {
			if ch.anomalies == nil {
				ch.anomalies, ch.anomalyDetail = map[string]int{}, map[string]string{}
			}
			ch.anomalies[an.name]++
			ch.anomalyDetail[an.name] = an.detail
		}
	} else {
		ch.responses++
		ch.download += m.bodyLen
		if random {
			ch.randomDn++
			ch.randomDnBytes += m.bodyLen
		}
	}
	if n := mythicInText(m.head); n > 0 {
		sigs = append(sigs, signature{Name: "mythic-agent-message", Kind: "c2", Weight: 0.97})
	}
	e.analyseCarriers(ch, m)
	ch.noteURIShape(c, m)
	ch.noteHTTPResidue(m, opaque)
	if sv := m.hdr["server"]; !m.req && sv != "" {
		if why, ok := c2DefaultServers[sv]; ok {
			if ch.respAnoms == nil {
				ch.respAnoms, ch.respAnomDetail = map[string]int{}, map[string]string{}
			}
			ch.respAnoms["server_c2_default"]++
			ch.respAnomDetail["server_c2_default"] = fmt.Sprintf("response Server: %q (%s)", sv, why)
		}
	}
	var sigNames []string
	for _, s := range sigs {
		if ch.sigHits == nil {
			ch.sigHits, ch.sigWeight = map[string]int{}, map[string]float64{}
		}
		ch.sigHits[s.Name]++
		ch.sigWeight[s.Name] = s.Weight
		sigNames = append(sigNames, s.Name)
	}
	if !opaque && a.N >= 64 && a.Score >= ch.maxRandom.Score {
		ch.maxRandom = a
	}
	e.matchFrameworkDefaults(ch, m)
	e.sigmaHTTP(c, m)
	if (random || len(sigs) > 0) && len(ch.notable) < 25 {
		line := fmt.Sprintf("%s %s", m.method, m.uri)
		dir := "request"
		if !m.req {
			line = fmt.Sprintf("%s %d", m.proto, m.status)
			dir = "response"
		}
		ch.notable = append(ch.notable, NotableMessage{
			Frame: m.frame, Time: m.ts.Format(time.RFC3339Nano), Direction: dir, Line: line,
			BodyBytes: m.bodyLen, Alphabet: string(a.Alphabet), Shannon: round2(a.Shannon),
			Random: round2(a.Score), Sigs: sigNames, CType: ctype,
		})
	}
}

type fileUpload struct {
	frame int64
	name  string
	bytes int64
	how   string
}

var filenameRe = regexp.MustCompile(`filename\*?=(?:UTF-8'')?"?([^";\r\n]+)`)

// detectUpload recognises deliberate file transfers: multipart form uploads
// (filename in the part headers, which sit in the first bytes of the body)
// and PUT/raw-binary POST bodies.
func detectUpload(m *httpMsg) (fileUpload, bool) {
	if m.bodyLen < 1024 {
		return fileUpload{}, false
	}
	ct := strings.ToLower(m.hdr["content-type"])
	switch {
	case strings.HasPrefix(ct, "multipart/form-data"):
		name := "<unnamed part>"
		if mm := filenameRe.FindSubmatch(m.head); mm != nil {
			name = string(mm[1])
		}
		return fileUpload{m.frame, name, m.bodyLen, "multipart " + m.method}, true
	case m.method == "PUT":
		return fileUpload{m.frame, m.uri, m.bodyLen, "PUT"}, true
	}
	return fileUpload{}, false
}

type anomaly struct{ name, detail string }

// User-Agent strings treated as C2 hints by this detector; labels below are
// configured heuristic attributions, not universal defaults.
var c2DefaultUAs = map[string]string{
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36": "Havoc default",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko":                                          "PowerShell Empire default",
	"Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko":                                                 "Mythic http/websocket profile default",
	covenantUA: "Covenant default (DefaultHttpProfile.yaml)",
	merlinUA:   "Merlin agent default",
}

// Response Server values treated as C2 hints by this detector; listed labels
// are heuristic attributions, not universal defaults.
var c2DefaultServers = map[string]string{
	"NetDNA-cache/2.2": "Mythic http profile default server header",
}

var chromeRe = regexp.MustCompile(`(?:Chrome|Chromium)/(\d+)\.`)
var msieRe = regexp.MustCompile(`MSIE ([0-9]+)\.`)

// expectedChromeMajor estimates the current stable Chrome major version at
// time t (Chrome 122 shipped 2024-02-20; one major every 4 weeks).
func expectedChromeMajor(t time.Time) int {
	anchor := time.Date(2024, 2, 20, 0, 0, 0, 0, time.UTC)
	return 122 + int(math.Floor(t.Sub(anchor).Hours()/24/28))
}

func (e *Engine) requestAnomalies(m *httpMsg) []anomaly {
	var out []anomaly
	ua := m.hdr["user-agent"]
	if why, ok := c2DefaultUAs[ua]; ok {
		out = append(out, anomaly{"ua_c2_default", "User-Agent is the " + why})
	}
	if ua == "" {
		out = append(out, anomaly{"ua_missing", "no User-Agent header"})
	}
	browserish := strings.HasPrefix(ua, "Mozilla/")
	_, hasLang := m.hdr["accept-language"]
	_, hasEnc := m.hdr["accept-encoding"]
	if browserish && !hasLang && !hasEnc {
		out = append(out, anomaly{"ua_browser_without_browser_headers",
			"claims to be a browser but sends no Accept-Language/Accept-Encoding"})
	}
	if mm := chromeRe.FindStringSubmatch(ua); mm != nil {
		v, _ := strconv.Atoi(mm[1])
		exp := expectedChromeMajor(m.ts)
		if v > 0 && exp-v >= 12 {
			out = append(out, anomaly{"ua_stale_browser",
				fmt.Sprintf("Chrome/%d is ~%d releases behind the Chrome/%d expected on %s", v, exp-v, exp, m.ts.Format("2006-01-02"))})
		}
	}
	if mm := msieRe.FindStringSubmatch(ua); mm != nil {
		out = append(out, anomaly{"ua_legacy_msie", "MSIE " + mm[1] + " User-Agent (common C2 profile default)"})
	}
	if m.bodyLen > 0 || m.method == "POST" {
		ct := strings.TrimSpace(m.hdr["content-type"])
		if ct == "*/*" || ct == "" {
			out = append(out, anomaly{"invalid_request_content_type", fmt.Sprintf("request Content-Type %q is not a real media type", ct)})
		}
	}
	if strings.Contains(strings.ToLower(m.hdr["cache-control"]), "no-cache") && strings.Contains(strings.ToLower(m.hdr["pragma"]), "no-cache") && m.method == "POST" {
		out = append(out, anomaly{"no_cache_post", "POST with Cache-Control: no-cache + Pragma: no-cache"})
	}
	host := strings.Split(m.hdr["host"], ":")[0]
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && m.method == "POST" {
		out = append(out, anomaly{"post_to_ip_literal", "POST to a bare IP address (no hostname)"})
	}
	return out
}

func round2(x float64) float64 { return math.Round(x*100) / 100 }

// Location budgets per channel: request locations keep the v10 budget of
// 24; response locations (v11a N1) get their own 8 so they can never
// crowd a request location out.
const (
	maxReqCarriers  = 24
	maxRespCarriers = 8
)

// decoded is one token's decoding.
type decoded struct {
	b             []byte
	enc, pre, suf string
	run           string           // the encoded run (token minus wrapper)
	words         *stats.Histogram // streamed word-run body (F03): decoded-byte histogram
}

// decodeCarrier decodes one carrier token. Request tokens are
// query-unescaped as in v10; response tokens are not. A response body
// whose streamed word-run decoder accepted the whole body (F03) decodes
// as "english" from the stream, which saw every body byte.
func decodeCarrier(m *httpMsg, t token) decoded {
	v := t.val
	if m.req {
		if u, err := url.QueryUnescape(v); err == nil {
			v = u
		}
	} else if t.loc == "resp:body" && m.words != nil {
		if h, ok := m.words.result(); ok {
			return decoded{enc: "english", words: h}
		}
	}
	b, enc, pre, suf := decodeUnescaped(v)
	return decoded{b: b, enc: enc, pre: pre, suf: suf}
}

func (d decoded) assess() stats.Assessment {
	if d.words != nil {
		return stats.Assess(d.words)
	}
	return stats.AssessBytes(d.b)
}

// streamBodyWords enables the streamed word-run body decoder (F03;
// mutation hook).
var streamBodyWords = true

// carrierResponses enables response carriers (v11a N1; mutation hook).
var carrierResponses = true

// analyseCarriers decodes every request and response token and tracks, per
// location, how often it carries fresh random data or matches the UUID-prefix
// message heuristic.
func (e *Engine) analyseCarriers(ch *httpChannel, m *httpMsg) {
	var toks []token
	if m.req {
		toks = requestTokens(m)
	} else if carrierResponses {
		toks = responseTokens(m)
	}
	e.collectCandidates(ch, m, toks)
	seenLoc := map[string]bool{}
	for _, t := range toks {
		loc := t.loc
		cs := ch.carriers[loc]
		d := decodeCarrier(m, t)
		if cs == nil {
			if m.req && ch.reqCarriers >= maxReqCarriers || !m.req && ch.respCarriers >= maxRespCarriers {
				continue
			}
			// A response location is created by its first token that
			// decodes (or matches the UUID-prefix message heuristic): ordinary pages and
			// one-shot responses allocate nothing (flow-heavy memory).
			if !m.req && d.enc == "raw" && !isMythicMessage(d.b) {
				continue
			}
			cs = &carrierStats{values: map[string]bool{}, encs: map[string]int{}, resp: !m.req}
			if ch.carriers == nil {
				ch.carriers = map[string]*carrierStats{}
			}
			ch.carriers[loc] = cs
			if m.req {
				ch.reqCarriers++
			} else {
				ch.respCarriers++
			}
		}
		if !seenLoc[loc] {
			cs.requests++
			seenLoc[loc] = true
		}
		key := valueKey(cs.resp, t.val)
		fresh := !cs.values[key]
		if fresh && len(cs.values) < 5000 {
			cs.values[strings.Clone(key)] = true // don't pin the header block
		}
		a := d.assess()
		cs.encs[d.enc]++
		if d.enc != "raw" {
			cs.noteWrapper(d.pre, d.suf)
		}
		random := fresh && a.Score >= 0.8 && a.N >= 24
		// F02: a run inside document syntax is a field value of a
		// structured response, counted apart (see scoreCarriers).
		structural := t.loc == "resp:body" && d.enc != "raw" && isStructural(d.pre, d.suf)
		// Response tokens count only when they decoded: a raw random
		// body is random_payloads' evidence, not a carrier's.
		switch {
		case !random || cs.resp && d.enc == "raw":
		case structural:
			cs.structRandom++
		default:
			cs.random++
		}
		if random && !(cs.resp && d.enc == "raw") && cs.example == "" {
			cs.example = strings.Clone(t.val)
			if len(cs.example) > 60 {
				cs.example = cs.example[:60] + "…"
			}
		}
		if isMythicMessage(d.b) {
			cs.mythic++
		}
	}
}

// wsPushHeader recognizes a case-insensitive "push" token in this header;
// that token alone does not identify a profile.
func wsPushHeader(v string) bool {
	for _, p := range strings.Split(v, ",") {
		if strings.EqualFold(strings.TrimSpace(p), "push") {
			return true
		}
	}
	return false
}

// incr counts k in m, copying k on first insert: header values are
// substrings of the message's header block, and a long-lived map key would
// otherwise keep the whole block alive (v9c 3.3).
func incr(m map[string]int, k string) {
	if _, ok := m[k]; ok {
		m[k]++
		return
	}
	m[strings.Clone(k)] = 1
}

// uaDest is one (server, Host) a User-Agent was sent to; uaDests records
// whether a host used a UA toward one destination or several (v9c 3.3:
// replaces a per-connection set — only "one" vs "two or more" is read).
type uaDest struct {
	server netip.AddrPort
	host   string
}

type uaDests struct {
	first uaDest
	multi bool
}

func (u *uaDests) count() int {
	switch {
	case u == nil:
		return 0
	case u.multi:
		return 2
	}
	return 1
}
