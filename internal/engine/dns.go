package engine

import (
	"encoding/binary"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"c2parser/internal/stats"
)

// DNS analysis. Tunnels (iodine, dnscat2, DNSExfiltrator, Cobalt Strike /
// Sliver DNS listeners) all have to smuggle data in the *query name*,
// because that is the only part a recursive resolver forwards. So per
// registrable domain we measure: how many distinct subdomains, how long,
// how random (against the right alphabet), how many bytes that encodes,
// what record types carry the replies, and how regular the timing is.

const (
	maxUniqueSubs  = 200000
	maxLabelSample = 20000
	dnsRetryWindow = 3.0 // seconds
)

type dnsSeries struct {
	t, size []float64
}

type dnsDomain struct {
	base      string
	queries   int
	responses int
	nx        int
	qtypes    map[string]int
	subs      map[string]struct{}
	subChars  int
	maxLabel  int
	txtBytes  int64
	clients   map[netip.Addr]*dnsSeries
	samples   []string
	answers   map[netip.Addr]bool
	// retry/multi-type de-duplication: the same client asking for the same
	// name within dnsRetryWindow is one logical query (Sliver repeats each
	// name ~3×, which pulls a naive unique/total ratio down to ~0.33).
	logical   int
	retries   int
	lastSeen  map[string]float64
	labels    []string // first label of each unique subdomain (positional analysis)
	luiseSum  float64  // Σ per-name Shannon entropy, Luise's definition
	luiseMax  float64
	answerRRs int
	ttl0      int
	dataResps int // responses carrying ≥4 A/AAAA records (data, not destinations)
	// Cobalt Strike DNS beacon defaults (see csDNSSignal).
	csPrefixNames int             // unique names shaped <cdn|www6|api|www|post>.<hex>…
	csPrefixes    map[string]bool // which of those prefixes appeared
	csStage       int             // names with the default stager marker
	csSample      string
	aAnswers      int // A records in answers
	zeroA         int // A records answering 0.0.0.0 (CS dns_idle default)
	ttl1          int // answers with TTL exactly 1 (CS dns_ttl default)
	first, last   time.Time
	firstFrame    int64
}

type dnsClient struct {
	queries int
	nxBases map[string]int
	nxHist  stats.Histogram // second-level labels of NXDOMAIN names
}

type dnsState struct {
	domains map[string]*dnsDomain
	clients map[netip.Addr]*dnsClient
	// question name by (client, server, id) so responses with no question
	// section can still be attributed.
	pend map[dnsKey]string
}

type dnsKey struct {
	client netip.AddrPort
	id     uint16
}

func newDNSState() *dnsState {
	return &dnsState{domains: map[string]*dnsDomain{}, clients: map[netip.Addr]*dnsClient{}, pend: map[dnsKey]string{}}
}

var dnsNoiseSuffixes = []string{".local", ".arpa", ".lan", ".home", ".internal", ".localdomain", ".corp", ".home.arpa"}

func (e *Engine) dnsIgnored(name string) bool {
	if !strings.Contains(name, ".") {
		return true
	}
	for _, s := range dnsNoiseSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	for _, s := range e.cfg.DNSAllow {
		s = strings.ToLower(strings.TrimPrefix(s, "."))
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

func (e *Engine) dnsDomain(base string, ts time.Time, frame int64) *dnsDomain {
	d := e.dns.domains[base]
	if d == nil {
		d = &dnsDomain{base: base, qtypes: map[string]int{}, subs: map[string]struct{}{}, clients: map[netip.Addr]*dnsSeries{}, first: ts, firstFrame: frame}
		e.dns.domains[base] = d
	}
	d.last = ts
	return d
}

func (e *Engine) dnsClient(a netip.Addr) *dnsClient {
	c := e.dns.clients[a]
	if c == nil {
		c = &dnsClient{nxBases: map[string]int{}}
		e.dns.clients[a] = c
	}
	return c
}

func (e *Engine) onDNSPayload(payload []byte, src, dst netip.AddrPort, ts time.Time, frame int64) {
	var msg layers.DNS
	if !decodeDNS(&msg, payload) {
		e.counters.DNSDecodeErrors++
		return
	}
	if !msg.QR {
		e.onDNSQuery(&msg, src, dst, ts, frame)
	} else {
		e.onDNSResponse(&msg, dst, src, ts, frame)
	}
}

func (e *Engine) onDNSQuery(msg *layers.DNS, client, server netip.AddrPort, ts time.Time, frame int64) {
	for _, q := range msg.Questions {
		name := strings.TrimSuffix(strings.ToLower(string(q.Name)), ".")
		e.counters.DNSQueries++
		e.sigmaDNS(name, q.Type.String(), msg.Z, nil, "", false, client, server, ts, frame)
		e.dns.pend[dnsKey{client, msg.ID}] = name
		if e.dnsIgnored(name) {
			continue
		}
		base := baseDomain(name)
		sub := strings.TrimSuffix(strings.TrimSuffix(name, base), ".")
		d := e.dnsDomain(base, ts, frame)
		d.queries++
		d.qtypes[q.Type.String()]++
		if csStageMarker(name) {
			d.csStage++
			d.csSample = name
		}
		e.dnsClient(client.Addr()).queries++
		now := e.rel(ts)
		if d.lastSeen == nil || len(d.lastSeen) > 100000 {
			d.lastSeen = map[string]float64{}
		}
		lk := client.Addr().String() + "|" + name
		last, seen := d.lastSeen[lk]
		d.lastSeen[lk] = now
		if seen && now-last < dnsRetryWindow {
			d.retries++
			continue // retry or A/AAAA/TXT twin: not a new logical query
		}
		d.logical++
		s := d.clients[client.Addr()]
		if s == nil {
			s = &dnsSeries{}
			d.clients[client.Addr()] = s
		}
		if e.room(len(s.t)) {
			s.t = append(s.t, now) // beacon timing uses logical queries only
			s.size = append(s.size, float64(len(name)))
		}
		if sub == "" {
			continue
		}
		if _, seen := d.subs[sub]; seen || len(d.subs) >= maxUniqueSubs {
			continue
		}
		d.subs[sub] = struct{}{}
		if pfx, ok := csDNSPrefix(sub); ok {
			d.csPrefixNames++
			if d.csPrefixes == nil {
				d.csPrefixes = map[string]bool{}
			}
			d.csPrefixes[pfx] = true
			if d.csSample == "" {
				d.csSample = name
			}
		}
		if len(d.labels) < maxLabelSample {
			d.labels = append(d.labels, strings.SplitN(sub, ".", 2)[0])
		}
		le := luiseEntropy(name)
		d.luiseSum += le
		if le > d.luiseMax {
			d.luiseMax = le
		}
		stripped := strings.ReplaceAll(sub, ".", "")
		d.subChars += len(stripped)
		for _, l := range strings.Split(sub, ".") {
			if len(l) > d.maxLabel {
				d.maxLabel = len(l)
			}
		}
		d.addSample(name)
	}
}

func (d *dnsDomain) addSample(name string) {
	d.samples = append(d.samples, name)
	sort.Slice(d.samples, func(i, j int) bool { return len(d.samples[i]) > len(d.samples[j]) })
	if len(d.samples) > 5 {
		d.samples = d.samples[:5]
	}
}

var rcodeNames = map[layers.DNSResponseCode]string{0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

func answerStrings(msg *layers.DNS) []string {
	var out []string
	for _, a := range msg.Answers {
		switch {
		case a.IP != nil:
			out = append(out, a.IP.String())
		case len(a.TXTs) > 0:
			for _, t := range a.TXTs {
				out = append(out, string(t))
			}
		case len(a.CNAME) > 0:
			out = append(out, string(a.CNAME))
		case len(a.PTR) > 0:
			out = append(out, string(a.PTR))
		}
	}
	return out
}

func (e *Engine) onDNSResponse(msg *layers.DNS, client, server netip.AddrPort, ts time.Time, frame int64) {
	e.counters.DNSResponses++
	name := ""
	if len(msg.Questions) > 0 {
		name = strings.TrimSuffix(strings.ToLower(string(msg.Questions[0].Name)), ".")
	} else {
		name = e.dns.pend[dnsKey{client, msg.ID}]
	}
	delete(e.dns.pend, dnsKey{client, msg.ID})
	if name != "" && e.sigmaOn("dns") {
		qt := ""
		if len(msg.Questions) > 0 {
			qt = msg.Questions[0].Type.String()
		}
		rc := rcodeNames[msg.ResponseCode]
		if rc == "" {
			rc = strconv.Itoa(int(msg.ResponseCode))
		}
		e.sigmaDNS(name, qt, msg.Z, answerStrings(msg), rc, true, client, server, ts, frame)
	}
	for _, a := range msg.Answers {
		if a.IP != nil && (a.Type == layers.DNSTypeA || a.Type == layers.DNSTypeAAAA) {
			if ip, ok := netip.AddrFromSlice(a.IP); ok {
				owner := strings.TrimSuffix(strings.ToLower(string(a.Name)), ".")
				if name != "" {
					owner = name
				}
				e.addName(ip.Unmap(), owner)
				e.resolved[ip.Unmap()] = true
				e.dnsDomain(baseDomain(owner), ts, frame).answerIPs(ip.Unmap())
			}
		}
	}
	if name == "" || e.dnsIgnored(name) {
		return
	}
	base := baseDomain(name)
	d := e.dnsDomain(base, ts, frame)
	d.responses++
	if msg.ResponseCode == layers.DNSResponseCodeNXDomain {
		d.nx++
		c := e.dnsClient(client.Addr())
		if c.nxBases[base] == 0 {
			c.nxHist.Add([]byte(strings.Split(base, ".")[0]))
		}
		c.nxBases[base]++
	}
	addr := 0
	for _, a := range msg.Answers {
		d.answerRRs++
		if a.TTL == 0 {
			d.ttl0++
		}
		if a.TTL == 1 {
			d.ttl1++
		}
		if a.Type == layers.DNSTypeA {
			d.aAnswers++
			if a.IP != nil && a.IP.IsUnspecified() {
				d.zeroA++
			}
		}
		if a.Type == layers.DNSTypeA || a.Type == layers.DNSTypeAAAA {
			addr++
		}
		switch a.Type {
		case layers.DNSTypeTXT:
			for _, t := range a.TXTs {
				d.txtBytes += int64(len(t))
			}
		case layers.DNSTypeNULL:
			d.txtBytes += int64(len(a.Data))
		}
	}
	if addr >= 4 {
		d.dataResps++
	}
}

// luiseEntropy reproduces the per-name metric from Luise (2024): Shannon
// entropy over a-z, '-', 0-9 with probabilities normalised by the full
// name length (dots included). Reported for comparison only: a name of n
// characters can never exceed log2(n) bits, so it can't separate encoded
// labels from ordinary hostnames.
func luiseEntropy(name string) float64 {
	if name == "" {
		return 0
	}
	var f [256]int
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
			f[c]++
		}
	}
	h, n := 0.0, float64(len(name))
	for _, c := range f {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// dnsTCPHalf handles DNS over TCP (2-byte length prefix framing).
type dnsTCPHalf struct {
	e      *Engine
	c      *tcpConn
	client bool
	buf    []byte
}

func (h *dnsTCPHalf) gap()            { h.buf = h.buf[:0] }
func (h *dnsTCPHalf) close(time.Time) {}
func (h *dnsTCPHalf) feed(data []byte, ts time.Time, frame int64) {
	h.buf = append(h.buf, data...)
	for len(h.buf) >= 2 {
		l := int(binary.BigEndian.Uint16(h.buf))
		if len(h.buf) < 2+l {
			return
		}
		src, dst := h.c.client, h.c.server
		if !h.client {
			src, dst = dst, src
		}
		h.e.onDNSPayload(h.buf[2:2+l], src, dst, ts, frame)
		h.buf = h.buf[2+l:]
	}
}

// decodeDNS wraps gopacket's decoder, which panics on some truncated
// questions (v1.1.19, found by fuzzing). One hostile packet must not end
// the analysis of a whole capture.
func decodeDNS(msg *layers.DNS, payload []byte) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return msg.DecodeFromBytes(payload, gopacket.NilDecodeFeedback) == nil
}

func (d *dnsDomain) answerIPs(a netip.Addr) {
	if d.answers == nil {
		d.answers = map[netip.Addr]bool{}
	}
	if len(d.answers) < 10000 {
		d.answers[a] = true
	}
}

// subHistogram is the byte histogram of every unique subdomain (dots
// removed). Built at scoring time from subs — the same set, in any order —
// instead of carrying a 2 KB histogram per base domain (v9c 3.3).
func (d *dnsDomain) subHistogram() (h stats.Histogram) {
	for sub := range d.subs {
		h.Add([]byte(strings.ReplaceAll(sub, ".", "")))
	}
	return h
}
