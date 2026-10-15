package engine

import (
	"fmt"
	"math"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"time"

	"c2parser/internal/sigma"
	"c2parser/internal/stats"
)

// Sigma integration: the engine renders what it parsed into the field names
// Sigma's logsources expect (proxy / webserver / dns / Zeek http, dns,
// smb_files, dce_rpc, x509, rdp, conn / firewall) and runs the loaded rules
// on each record. Hits become findings and corroborate existing ones.

const CatSigma = "Sigma rule match"
const CatLateral = "Lateral movement (DCE/RPC)"

type sigmaHit struct {
	rule           *sigma.Rule
	client, server netip.Addr
	port           uint16
	count          int
	frames         []int64
	first, last    time.Time
	sample         string
}

func (e *Engine) sigmaOn(kind string) bool { return len(e.sigma[kind]) > 0 }

func addrFields(ev sigma.Event, client, server netip.AddrPort) {
	ev["src_ip"] = []string{client.Addr().String()}
	ev["dst_ip"] = []string{server.Addr().String()}
	ev["src_port"] = []string{strconv.Itoa(int(client.Port()))}
	ev["dst_port"] = []string{strconv.Itoa(int(server.Port()))}
	ev["id.orig_h"], ev["id.resp_h"] = ev["src_ip"], ev["dst_ip"]
	ev["id.orig_p"], ev["id.resp_p"] = ev["src_port"], ev["dst_port"]
}

func (e *Engine) emitSigma(kind string, ev sigma.Event, client, server netip.AddrPort, ts time.Time, frame int64, sample string) {
	for _, r := range e.sigma[kind] {
		if !r.Match(ev) {
			continue
		}
		key := r.File + "|" + client.Addr().String() + "|" + server.Addr().String()
		h := e.sigmaHits[key]
		if h == nil {
			h = &sigmaHit{rule: r, client: client.Addr(), server: server.Addr(), port: server.Port(), first: ts, sample: sample}
			e.sigmaHits[key] = h
			e.sigmaOrder = append(e.sigmaOrder, key)
		}
		h.count++
		h.last = ts
		if len(h.frames) < 8 && frame > 0 {
			h.frames = append(h.frames, frame)
		}
	}
}

// ------------------------------------------------------------------ HTTP

type pendingHTTPEvent struct {
	ev     sigma.Event
	ts     time.Time
	frame  int64
	sample string
}

func httpEvent(m *httpMsg, c *tcpConn) sigma.Event {
	host := m.hdr["host"]
	hostOnly := strings.Trim(strings.Split(host, ":")[0], "[]")
	uri := m.uri
	p, q, _ := strings.Cut(uri, "?")
	ext := strings.TrimPrefix(path.Ext(p), ".")
	full := "http://" + host + uri
	ua := m.hdr["user-agent"]
	ev := sigma.Event{
		"c-uri": {uri, full}, "cs-uri": {uri, p}, "uri": {uri},
		"c-uri-stem": {p}, "cs-uri-stem": {p}, "c-uri-query": {q}, "cs-uri-query": {uri, q}, "c-uri-extension": {ext},
		"c-useragent": {ua}, "cs-user-agent": {ua}, "user_agent": {ua},
		"cs-method": {m.method}, "method": {m.method},
		"cs-host": {hostOnly}, "host": {hostOnly}, "r-dns": {hostOnly},
		"cs-referrer": {m.hdr["referer"]}, "cs-referer": {m.hdr["referer"]}, "referrer": {m.hdr["referer"]},
		"cs-cookie": {m.hdr["cookie"]}, "cs-version": {m.proto}, "version": {m.proto},
		"cs-bytes": {strconv.FormatInt(m.bodyLen, 10)}, "request_body_len": {strconv.FormatInt(m.bodyLen, 10)},
		"cs-content-type": {m.hdr["content-type"]},
	}
	for k, v := range ev {
		if len(v) == 1 && v[0] == "" {
			delete(ev, k) // absent, so `null` matches and `exists` is honest
		}
	}
	addrFields(ev, c.client, c.server)
	return ev
}

func (e *Engine) sigmaHTTP(c *tcpConn, m *httpMsg) {
	if !e.sigmaOn("http") {
		return
	}
	if m.req {
		if len(c.sigmaPend) < 64 {
			c.sigmaPend = append(c.sigmaPend, pendingHTTPEvent{httpEvent(m, c), m.ts, m.frame, m.method + " " + m.uri})
		}
		return
	}
	if len(c.sigmaPend) == 0 {
		return
	}
	p := c.sigmaPend[0]
	c.sigmaPend = c.sigmaPend[1:]
	p.ev["sc-status"] = []string{strconv.Itoa(m.status)}
	p.ev["status_code"] = p.ev["sc-status"]
	p.ev["sc-bytes"] = []string{strconv.FormatInt(m.bodyLen, 10)}
	p.ev["response_body_len"] = p.ev["sc-bytes"]
	if ct := m.hdr["content-type"]; ct != "" {
		p.ev["resp_mime_types"] = []string{ct}
	}
	e.emitSigma("http", p.ev, c.client, c.server, p.ts, p.frame, p.sample)
}

func (e *Engine) flushSigmaHTTP(c *tcpConn) {
	for _, p := range c.sigmaPend {
		e.emitSigma("http", p.ev, c.client, c.server, p.ts, p.frame, p.sample)
	}
	c.sigmaPend = nil
}

// ------------------------------------------------------------------- DNS

func (e *Engine) sigmaDNS(name, qtype string, z uint8, answers []string, rcode string, resp bool, client, server netip.AddrPort, ts time.Time, frame int64) {
	if !e.sigmaOn("dns") {
		return
	}
	ev := sigma.Event{"query": {name}, "QueryName": {name}, "record_type": {qtype}, "qtype_name": {qtype}, "Z": {strconv.Itoa(int(z))}}
	if resp {
		ev["answer"] = answers
		ev["answers"] = answers
		ev["rcode_name"] = []string{rcode}
	}
	addrFields(ev, client, server)
	e.emitSigma("dns", ev, client, server, ts, frame, qtype+" "+name)
}

// --------------------------------------------------------------- SMB/RPC

func (e *Engine) sigmaSMBFile(f *smbFile, ts time.Time, frame int64) {
	if !e.sigmaOn("smb_files") || !f.NameKnown {
		return
	}
	c := f.st.c
	ev := sigma.Event{"path": {f.Share}, "name": {strings.TrimLeft(f.Name, `\`)}, "action": {"SMB::FILE_OPEN"}}
	addrFields(ev, c.client, c.server)
	e.emitSigma("smb_files", ev, c.client, c.server, ts, frame, f.label())
}

func (e *Engine) emitDCERPC(client, server netip.AddrPort, endpoint, op, pipe string, ts time.Time, frame int64) {
	if !e.sigmaOn("dce_rpc") {
		return
	}
	ev := sigma.Event{"endpoint": {endpoint}, "operation": {zeekOpName(endpoint, op)}}
	if pipe != "" {
		ev["named_pipe"] = []string{pipe}
	}
	addrFields(ev, client, server)
	e.emitSigma("dce_rpc", ev, client, server, ts, frame, endpoint+"::"+zeekOpName(endpoint, op))
}

// ----------------------------------------------------------- TLS / conns

func (e *Engine) sigmaX509(c *tcpConn, ci *certInfo) {
	if !e.sigmaOn("x509") || ci == nil || ci.cert == nil {
		return
	}
	ev := sigma.Event{"certificate.serial": {strings.ToUpper(ci.cert.SerialNumber.Text(16))},
		"certificate.subject": {ci.Subject}, "certificate.issuer": {ci.Issuer}, "san.dns": ci.DNSNames}
	addrFields(ev, c.client, c.server)
	e.emitSigma("x509", ev, c.client, c.server, c.start, c.firstFrame, ci.Subject)
}

func (e *Engine) sigmaConn(client, server netip.AddrPort, proto, service string, ts time.Time, frame int64) {
	ev := sigma.Event{"proto": {proto}, "service": {service}}
	addrFields(ev, client, server)
	if e.sigmaOn("conn") {
		e.emitSigma("conn", ev, client, server, ts, frame, fmt.Sprintf("%s/%d", proto, server.Port()))
	}
	if service == "rdp" && e.sigmaOn("rdp") {
		e.emitSigma("rdp", ev, client, server, ts, frame, "rdp")
	}
}

// --------------------------------------------------------------- scoring

var sigmaLevelWeight = map[string]float64{"informational": 0.15, "low": 0.3, "medium": 0.5, "high": 0.75, "critical": 0.9}

func (e *Engine) scoreSigma(sc *scorer) {
	// Host-pair index of findings that already exist (v9 Phase 1.1): a Sigma
	// hit folds into the matching (client, server) finding — preferring the
	// C2 channel on the hit's port — instead of a duplicate standalone
	// "Sigma rule match" finding. Standalone only when no finding exists.
	pair := map[string]*acc{}
	for _, k := range sc.order {
		a := sc.accs[k]
		pk := a.f.Client + "|" + a.f.Server
		if _, ok := pair[pk]; !ok && a.f.Client != "" && a.f.Server != "" {
			pair[pk] = a
		}
	}
	for _, key := range e.sigmaOrder {
		h := e.sigmaHits[key]
		r := h.rule
		w := sigmaLevelWeight[r.Level]
		if w == 0 {
			w = 0.3
		}
		s := 0.7 + 0.3*(1-math.Exp(-float64(h.count-1)/5))
		sig := stats.Signal{Name: "sigma:" + shortID(r), Weight: w, Score: s,
			Detail: fmt.Sprintf("[%s] %s — %d matching %s events, e.g. %q", r.Level, r.Title, h.count, r.Kind, h.sample)}
		host := sc.accs[c2Key(h.client, h.server, h.port)]
		if host == nil {
			host = pair[h.client.String()+"|"+h.server.String()]
		}
		if host != nil {
			host.add(sig)
			host.evidence("Sigma rule %s (%s) %s", r.ID, strings.Join(r.Tags, " "), r.File)
			host.frames(h.frames...)
			continue
		}
		title := fmt.Sprintf("Sigma: %s (%s → %s)", r.Title, h.client, h.server)
		a := sc.get("sigma|"+key, CatSigma, title, h.client, h.server, h.first, h.last)
		a.add(sig)
		a.evidence("rule %s (%s) %s", r.ID, strings.Join(r.Tags, " "), r.File)
		a.frames(h.frames...)
	}
}

func shortID(r *sigma.Rule) string {
	if r.ID != "" && len(r.ID) >= 8 {
		return r.ID[:8]
	}
	return strings.TrimSuffix(path.Base(r.File), path.Ext(r.File))
}
