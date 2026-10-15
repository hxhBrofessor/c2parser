// Package engine turns packets into scored findings: C2 channels (HTTP and
// generic beaconing), SMB named-pipe pivots, DNS tunnelling / DGA, and data
// exfiltration.
package engine

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"

	"c2parser/internal/pcapio"
	"c2parser/internal/sigma"
	"c2parser/internal/stats"
)

// Config tunes the engine. Zero values are replaced by defaults.
type Config struct {
	DCs            []netip.Addr       // hosts declared as domain controllers (-dc), added to those inferred from 88/389/drsuapi
	Internal       []netip.Prefix     // what counts as "inside"
	LegacyEntropy  float64            // raw Shannon threshold kept for continuity (presentation used 7.80)
	ExfilHalfBytes int64              // upload volume at which the volume signal reaches 0.5
	ExfilMinBytes  int64              // ignore channels that uploaded less than this
	BurstGap       time.Duration      // client→server silence that ends a "burst"
	Beacon         stats.BeaconParams // min/full event counts
	DNSAllow       []string           // domain suffixes excluded from DNS tunnel scoring
	AllPairs       bool               // also score internal↔internal pairs for beaconing/exfil
	MaxChannelEvts int                // cap on stored events per series (channel bursts, HTTP requests, DNS queries, pipe ops, WebSocket messages)
	MaxSummaryRows int                // cap on rows per summary table (http_channels, dns_domains); 0 = default
	IOCs           []IOC              // user-supplied indicators (see ParseIOCLine)
	Sigma          []*sigma.Rule      // compiled Sigma rules to run on derived events
	RecordConns    bool               // keep a per-connection table in Result.Conns (eval label joins, v10a 1.2)
	TimingV2       bool               // v8 statistics engine: timing v2, name-keyed series, signal families
}

func (c *Config) defaults() {
	if c.LegacyEntropy == 0 {
		c.LegacyEntropy = 7.80
	}
	if c.ExfilHalfBytes == 0 {
		c.ExfilHalfBytes = 1 << 20
	}
	if c.ExfilMinBytes == 0 {
		c.ExfilMinBytes = 256 << 10
	}
	if c.BurstGap == 0 {
		c.BurstGap = 250 * time.Millisecond
	}
	if c.Beacon.MinEvents == 0 {
		c.Beacon = stats.DefaultBeaconParams
	}
	if c.MaxSummaryRows == 0 {
		c.MaxSummaryRows = 5000
	}
	if c.MaxChannelEvts == 0 {
		c.MaxChannelEvts = 200000
	}
}

// Counters are capture-level statistics.
type Counters struct {
	Packets      int64 `json:"packets"`
	Bytes        int64 `json:"bytes"`
	DecodeErrors int64 `json:"decode_errors"`
	NonIP        int64 `json:"non_ip"`
	// SeriesEventsDropped counts events not stored because a series reached
	// the per-series cap (-max-series-events); timing on those series is
	// judged on the first events only.
	SeriesEventsDropped int64 `json:"series_events_dropped,omitempty"`
	// QUICClientHellos counts ClientHellos recovered from QUIC Initial
	// packets; QUICInitialErrors counts client Initials that failed to
	// decrypt (truncated by snaplen, or not really QUIC).
	QUICInitialFlows  int64 `json:"quic_initial_flows,omitempty"` // UDP flows with ≥ 1 client Initial
	QUICClientHellos  int64 `json:"quic_client_hellos,omitempty"`
	QUICInitialErrors int64 `json:"quic_initial_errors,omitempty"`
	// SummaryRowsDropped counts http_channels / dns_domains rows beyond the
	// per-table cap (-max-summary-rows). Findings are unaffected.
	SummaryRowsDropped int64 `json:"summary_rows_dropped,omitempty"`
	Decapsulated       int64 `json:"decapsulated,omitempty"` // packets analysed inside GRE / ERSPAN / VXLAN / IP-in-IP
	TCPPackets         int64 `json:"tcp_packets"`
	UDPPackets         int64 `json:"udp_packets"`
	TCPConns           int   `json:"tcp_connections"`
	UDPFlows           int   `json:"udp_flows"`
	HTTPMessages       int   `json:"http_messages"`
	SMBMessages        int   `json:"smb_messages"`
	DNSQueries         int   `json:"dns_queries"`
	DNSResponses       int   `json:"dns_responses"`
	DNSDecodeErrors    int   `json:"dns_decode_errors"`
}

// Engine holds all state for one capture.
type Engine struct {
	leanGC       bool                  // this engine switched the GC to lean mode (gc.go)
	tunnels      map[string]*tunnelAgg // HTTP CONNECT tunnels by client|target|proxy (v9c 2.3)
	tunOrder     []*tunnelAgg
	dcePorts     map[netip.AddrPort]dceLearned // dynamic DCE/RPC ports learned from ept_map / OXID (v10a 2.1)
	dceConns     []*dceConn                    // DCE/RPC associations on raw TCP
	ldapSessions []*ldapSession                // LDAP connections (v10a 2.2)
	udpRecs      []ConnRecord
	cfg          Config
	internal     []netip.Prefix

	epoch       time.Time
	first, last time.Time
	frame       int64
	counters    Counters

	tcp      map[connKey]*tcpConn
	allTCP   []*tcpConn
	udp      map[connKey]*udpFlow
	channels map[chanKey]*channel
	chOrder  []*channel

	httpChans map[httpChanKey]*httpChannel
	httpOrder []*httpChannel
	smbStates []*smbState
	dns       *dnsState
	names     map[netip.Addr]map[string]bool
	resolved  map[netip.Addr]bool // every IP seen in a DNS A/AAAA answer
	baselines map[string]*hostBaseline
	iocs      map[string]map[string]string // kind → value → label
	contacted map[netip.Addr]bool          // servers clients sent data to

	sigma        map[string][]*sigma.Rule // event kind → rules
	sigmaHits    map[string]*sigmaHit
	timingSeries []TimingSeries // v2 only
	sigmaOrder   []string

	asm *reassembly.Assembler
}

// New builds an engine.
func New(cfg Config) *Engine {
	cfg.defaults()
	internal := cfg.Internal
	if len(internal) == 0 {
		internal, _ = ParsePrefixes(DefaultInternal)
	}
	e := &Engine{
		cfg: cfg, internal: internal,
		tcp: map[connKey]*tcpConn{}, udp: map[connKey]*udpFlow{}, channels: map[chanKey]*channel{},
		httpChans: map[httpChanKey]*httpChannel{}, dns: newDNSState(), names: map[netip.Addr]map[string]bool{},
		resolved: map[netip.Addr]bool{}, baselines: map[string]*hostBaseline{},
	}
	e.sigma, e.sigmaHits = map[string][]*sigma.Rule{}, map[string]*sigmaHit{}
	for _, r := range cfg.Sigma {
		e.sigma[r.Kind] = append(e.sigma[r.Kind], r)
	}
	e.iocs = map[string]map[string]string{}
	for _, i := range cfg.IOCs {
		if e.iocs[i.Kind] == nil {
			e.iocs[i.Kind] = map[string]string{}
		}
		e.iocs[i.Kind][i.Value] = i.Label
	}
	e.asm = reassembly.NewAssembler(reassembly.NewStreamPool(&streamFactory{e: e}))
	e.asm.MaxBufferedPagesPerConnection = 16384
	e.asm.MaxBufferedPagesTotal = 1 << 20
	return e
}

// AnalyzeFile runs the full pipeline on one capture file.
func AnalyzeFile(path string, cfg Config) (*Result, error) {
	r, err := pcapio.Open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	e := New(cfg)
	defer e.releaseLeanGC()
	if err := e.Ingest(r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	res := e.Finish()
	res.File = path
	return res, nil
}

// Ingest consumes every packet from r.
func (e *Engine) Ingest(r pcapio.Reader) error {
	for {
		p, err := r.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		e.packet(p)
		if e.frame&0xffff == 0 {
			e.checkLeanGC()
		}
	}
}

type pktCtx struct {
	ci    gopacket.CaptureInfo
	frame int64
}

func (c *pktCtx) GetCaptureInfo() gopacket.CaptureInfo { return c.ci }

func (e *Engine) rel(t time.Time) float64 { return t.Sub(e.epoch).Seconds() }

// innermost returns the innermost IP layer and the TCP/UDP layer that
// follows it, so tunnelled traffic (GRE, ERSPAN, VXLAN, IP-in-IP — common
// on SPAN/mirror feeds) is analysed by its inner addresses. tunnelled
// reports more than one IP layer. 802.1Q/802.1ad tags need nothing here.
func innermost(pkt gopacket.Packet) (nl gopacket.NetworkLayer, tl gopacket.Layer, tunnelled bool) {
	nIP := 0
	for _, l := range pkt.Layers() {
		switch x := l.(type) {
		case *layers.IPv4, *layers.IPv6:
			nl, tl = x.(gopacket.NetworkLayer), nil
			nIP++
		case *layers.TCP, *layers.UDP:
			if nl != nil && tl == nil {
				tl = x
			}
		}
	}
	if nl == nil {
		return pkt.NetworkLayer(), pkt.TransportLayer(), false // non-IP network layers (ARP, …)
	}
	return nl, tl, nIP > 1
}

func (e *Engine) packet(p pcapio.Packet) {
	e.frame++
	e.counters.Packets++
	e.counters.Bytes += int64(len(p.Data))
	ts := p.Timestamp
	if e.epoch.IsZero() {
		e.epoch, e.first = ts, ts
	}
	if ts.After(e.last) {
		e.last = ts
	}
	pkt := gopacket.NewPacket(p.Data, p.LinkType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	nl, tlayer, tunnelled := innermost(pkt)
	if tunnelled {
		e.counters.Decapsulated++
	}
	if nl == nil {
		e.counters.NonIP++
		return
	}
	var src, dst netip.Addr
	switch ip := nl.(type) {
	case *layers.IPv4:
		if ip.Flags&layers.IPv4MoreFragments != 0 || ip.FragOffset != 0 {
			return // fragments: not reassembled
		}
		src, _ = netip.AddrFromSlice(ip.SrcIP)
		dst, _ = netip.AddrFromSlice(ip.DstIP)
	case *layers.IPv6:
		src, _ = netip.AddrFromSlice(ip.SrcIP)
		dst, _ = netip.AddrFromSlice(ip.DstIP)
	default:
		e.counters.NonIP++
		return
	}
	src, dst = src.Unmap(), dst.Unmap()
	if el := pkt.ErrorLayer(); el != nil && tlayer == nil {
		e.counters.DecodeErrors++
		return
	}
	switch tl := tlayer.(type) {
	case *layers.TCP:
		e.counters.TCPPackets++
		s := netip.AddrPortFrom(src, uint16(tl.SrcPort))
		d := netip.AddrPortFrom(dst, uint16(tl.DstPort))
		e.observeTCP(ts, s, d, tl)
		ctx := &pktCtx{ci: gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(p.Data), Length: p.OrigLen}, frame: e.frame}
		e.asm.AssembleWithContext(nl.NetworkFlow(), tl, ctx)
		if e.frame%20000 == 0 {
			e.asm.FlushCloseOlderThan(ts.Add(-2 * time.Minute))
			e.sweepConns(ts.Add(-2 * time.Minute))
		}
	case *layers.UDP:
		e.counters.UDPPackets++
		s := netip.AddrPortFrom(src, uint16(tl.SrcPort))
		d := netip.AddrPortFrom(dst, uint16(tl.DstPort))
		e.observeUDP(ts, s, d, tl.Payload)
		if tl.SrcPort == 53 || tl.DstPort == 53 {
			e.onDNSPayload(tl.Payload, s, d, ts, e.frame)
		}
	}
}

// Finish flushes reassembly and computes findings.
func (e *Engine) Finish() *Result {
	defer e.leanFinish()()
	e.asm.FlushAll()
	for _, c := range e.allTCP {
		e.finishConn(c)
	}
	for _, u := range e.udp {
		u.flush(e)
	}
	e.counters.TCPConns = len(e.allTCP)
	e.counters.UDPFlows = len(e.udp)
	for _, u := range e.udp {
		if u.q != nil && u.q.tries > 0 {
			e.counters.QUICInitialFlows++
		}
	}
	res := &Result{Counters: e.counters}
	if !e.first.IsZero() {
		res.Start = e.first.Format(time.RFC3339Nano)
		res.End = e.last.Format(time.RFC3339Nano)
		res.DurationSec = round2(e.last.Sub(e.first).Seconds())
	}
	res.Findings = e.score()
	res.Hosts = e.hostRisk(res.Findings)
	res.HTTP = e.httpSummaries()
	res.Pipes = e.smbSummaries()
	res.DNS = e.dnsSummaries()
	res.TopTalkers = e.topTalkers(15)
	res.Counters.SummaryRowsDropped = e.counters.SummaryRowsDropped
	res.RPCCalls = e.rpcCalls()
	if e.cfg.RecordConns {
		res.Conns = e.connRecords()
	}
	if e.cfg.TimingV2 {
		res.TimingMode = "v2"
		res.Timing = e.timingSeries
	}
	return res
}

func (e *Engine) addName(a netip.Addr, n string) {
	if n == "" {
		return
	}
	m := e.names[a]
	if m == nil {
		m = map[string]bool{}
		e.names[a] = m
	}
	if len(m) < 8 {
		m[n] = true
	}
}

func (e *Engine) namesOf(a netip.Addr) []string {
	var out []string
	for n := range e.names[a] {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// --------------------------------------------------------------- flows

type connKey struct{ a, b netip.AddrPort }

func mkKey(x, y netip.AddrPort) connKey {
	if x.Compare(y) <= 0 {
		return connKey{x, y}
	}
	return connKey{y, x}
}

type chanKey struct {
	client, server netip.Addr
	port           uint16
	proto          string
}

// channel aggregates every connection/flow between a client and a service.
type channel struct {
	key             chanKey
	conns           int
	out, in         int64
	pktsOut, pktsIn int64
	first, last     time.Time
	firstFrame      int64
	burstT, burstS  []float64
	inBurstS        []float64 // server→client burst sizes (keep-alive shape test)
	maxConnSec      float64
	tls             *tlsAgg
	quic            bool
	raw             *rawAgg
	// UDP payload shape (v9c D2: WireGuard keep-alives are 32 B both ways)
	udp32Out, udp32In int64
	quicHellos        int   // ClientHellos recovered from QUIC Initials (v10a 2.3)
	quicECH           int   // … of which carried encrypted_client_hello (SNI is the outer, public name)
	udpNonDNS         int64 // client payloads on server port 53 that don't parse as DNS
	// strongest single-connection upload asymmetry (see finishConn)
	bestConnExfil float64
	bestConnOut   int64
	bestConnIn    int64
	bestConnFrame int64
}

func (e *Engine) channel(client, server netip.AddrPort, proto string, ts time.Time) *channel {
	k := chanKey{client.Addr(), server.Addr(), server.Port(), proto}
	ch := e.channels[k]
	if ch == nil {
		ch = &channel{key: k, first: ts, firstFrame: e.frame}
		e.channels[k] = ch
		e.chOrder = append(e.chOrder, ch)
	}
	ch.last = ts
	return ch
}

func (ch *channel) addInBurst(e *Engine, n int64) {
	if e.room(len(ch.inBurstS)) {
		ch.inBurstS = append(ch.inBurstS, float64(n))
	}
}

func (ch *channel) addBurst(e *Engine, t time.Time, n int64) {
	if e.room(len(ch.burstT)) {
		ch.burstT = append(ch.burstT, e.rel(t))
		ch.burstS = append(ch.burstS, float64(n))
	}
}

// room reports whether a series holding n events may grow (Config.
// MaxChannelEvts); dropped events are counted in Counters.SeriesEventsDropped.
func (e *Engine) room(n int) bool {
	if n < e.cfg.MaxChannelEvts {
		return true
	}
	e.counters.SeriesEventsDropped++
	return false
}

type dirState struct {
	hi         uint32
	init       bool
	bytes      int64
	lastData   time.Time
	burstStart time.Time
	burstBytes int64
}

// advance returns how many bytes of this segment are new (not
// retransmitted), so volume isn't inflated by retransmissions.
func (d *dirState) advance(seq uint32, n int, syn bool) int {
	if syn {
		d.hi, d.init = seq+1, true
		return 0
	}
	if n == 0 {
		return 0
	}
	end := seq + uint32(n)
	if !d.init {
		d.hi, d.init = end, true
		return n
	}
	diff := int32(end - d.hi)
	if diff <= 0 {
		return 0
	}
	d.hi = end
	if int(diff) > n {
		return n
	}
	return int(diff)
}

type tcpConn struct {
	client, server netip.AddrPort
	start, last    time.Time
	firstFrame     int64
	closed         bool
	finished       bool
	c2s, s2c       dirState
	ch             *channel
	proto          string
	sni            string
	pendingMethods []string
	lastHost       string
	tunnel         bool        // HTTP CONNECT established
	connectTarget  string      // host:port of the last CONNECT request
	tunnelTarget   string      // host:port once the CONNECT succeeded
	tunTLS         [2]*tlsHalf // TLS parsers for the tunnel's inner session (v9c 2.3)
	websocket      bool        // 101 Switching Protocols → RFC 6455 frames
	wsPush         bool        // upgrade request carried "Accept-Type: Push" (server-push mode)
	tls            *tlsInfo
	tlsServerDone  bool
	sigmaPend      []pendingHTTPEvent
	// Parser state lives on the connection, not the reassembly stream, so
	// an idle stream that the assembler flushes and re-creates keeps its
	// SMB tree/FileId maps and HTTP framing.
	halves    [2]protoHalf
	sniffed   bool
	compacted bool // closed, reassembly complete, parser state released
}

// sweepConns forgets the 4-tuple lookup entry of compacted connections idle
// since before cut (v9c 3.3). The connection itself stays in allTCP for
// Finish; a packet on the same 4-tuple after this starts a new connection,
// as a reused port would.
func (e *Engine) sweepConns(cut time.Time) {
	if !compactClosed {
		return
	}
	for k, c := range e.tcp {
		if c.compacted && c.last.Before(cut) {
			delete(e.tcp, k)
		}
	}
}

func (e *Engine) observeTCP(ts time.Time, src, dst netip.AddrPort, t *layers.TCP) {
	k := mkKey(src, dst)
	c := e.tcp[k]
	syn := t.SYN && !t.ACK
	if c != nil && syn && (c.closed || ts.Sub(c.last) > 30*time.Second) {
		e.finishConn(c) // 4-tuple reused for a new connection
		c = nil
	}
	if c == nil {
		c = &tcpConn{start: ts, firstFrame: e.frame}
		switch {
		case syn:
			c.client, c.server = src, dst
		case t.SYN && t.ACK:
			c.client, c.server = dst, src
		case guessServerIsDst(src.Port(), dst.Port()):
			c.client, c.server = src, dst
		default:
			c.client, c.server = dst, src
		}
		c.ch = e.channel(c.client, c.server, "tcp", ts)
		c.ch.conns++
		e.tcp[k] = c
		e.allTCP = append(e.allTCP, c)
	}
	c.last = ts
	c.ch.last = ts
	if t.FIN || t.RST {
		c.closed = true
	}
	fromClient := src == c.client
	d := &c.s2c
	if fromClient {
		d = &c.c2s
	}
	n := d.advance(t.Seq, len(t.Payload), t.SYN)
	if n == 0 {
		return
	}
	d.bytes += int64(n)
	if fromClient {
		c.ch.out += int64(n)
		c.ch.pktsOut++
		if d.burstBytes > 0 && ts.Sub(d.lastData) > e.cfg.BurstGap {
			e.connBurst(c, d.burstStart, d.burstBytes)
			d.burstBytes = 0
		}
		if d.burstBytes == 0 {
			d.burstStart = ts
		}
		d.burstBytes += int64(n)
	} else {
		c.ch.in += int64(n)
		c.ch.pktsIn++
		if d.burstBytes > 0 && ts.Sub(d.lastData) > e.cfg.BurstGap {
			c.ch.addInBurst(e, d.burstBytes)
			d.burstBytes = 0
		}
		d.burstBytes += int64(n)
	}
	d.lastData = ts
}

func (e *Engine) finishConn(c *tcpConn) {
	if c.finished {
		return
	}
	c.finished = true
	for _, h := range c.halves {
		if h != nil {
			h.close(c.last) // flush read-until-close bodies etc.
		}
	}
	c.halves = [2]protoHalf{}
	e.flushSigmaHTTP(c)
	if len(e.sigma) > 0 {
		svc := c.proto
		if c.server.Port() == 3389 {
			svc = "rdp"
		}
		e.sigmaConn(c.client, c.server, "tcp", svc, c.start, c.firstFrame)
	}
	if c.c2s.burstBytes > 0 {
		e.connBurst(c, c.c2s.burstStart, c.c2s.burstBytes)
		c.c2s.burstBytes = 0
	}
	if c.s2c.burstBytes > 0 {
		c.ch.addInBurst(e, c.s2c.burstBytes)
		c.s2c.burstBytes = 0
	}
	if d := c.last.Sub(c.start).Seconds(); d > c.ch.maxConnSec {
		c.ch.maxConnSec = d
	}
	// Exfil is often one long upload connection hidden inside a channel
	// that also downloads (tasking, tool transfer). Score each connection
	// on its own so the channel total doesn't dilute it.
	if out := c.c2s.bytes; out >= e.cfg.ExfilMinBytes {
		if s := exfilShape(out, c.s2c.bytes, e.cfg.ExfilHalfBytes); s > c.ch.bestConnExfil {
			c.ch.bestConnExfil, c.ch.bestConnOut, c.ch.bestConnIn, c.ch.bestConnFrame = s, out, c.s2c.bytes, c.firstFrame
		}
	}
}

// pcr is the producer/consumer ratio (out−in)/(out+in): +1 pure upload,
// 0 balanced, −1 pure download.
func pcr(out, in int64) float64 {
	if out+in == 0 {
		return 0
	}
	return float64(out-in) / float64(out+in)
}

// exfilShape = volume × asymmetry. Volume saturates (half-credit at `half`
// bytes); asymmetry reaches full credit at PCR ≥ 0.5 (3:1 upload).
func exfilShape(out, in, half int64) float64 {
	return stats.Saturate(float64(out), float64(half)) * stats.Clamp01(pcr(out, in)/0.5)
}

type udpFlow struct {
	client, server netip.AddrPort
	ch             *channel
	last           time.Time
	burstStart     time.Time
	burstBytes     int64
	inLast         time.Time
	inBurstBytes   int64
	q              *quicFlow // QUIC Initial state (v10a 2.3)
	rec            int       // index+1 of the current Result.Conns record (RecordConns)
}

func (e *Engine) observeUDP(ts time.Time, src, dst netip.AddrPort, payload []byte) {
	n := len(payload)
	k := mkKey(src, dst)
	u := e.udp[k]
	if u == nil {
		u = &udpFlow{}
		if e.scopeOf(dst.Addr()) == scopeLocal { // multicast/broadcast: sender is the client
			u.client, u.server = src, dst
		} else if guessServerIsDst(src.Port(), dst.Port()) || !wellKnownServerPorts[src.Port()] && !wellKnownServerPorts[dst.Port()] {
			u.client, u.server = src, dst
		} else {
			u.client, u.server = dst, src
		}
		u.ch = e.channel(u.client, u.server, "udp", ts)
		u.ch.conns++
		e.udp[k] = u
	}
	u.ch.last = ts
	if e.cfg.RecordConns {
		e.recordUDP(u, ts)
	}
	if src == u.client && isQUICLongHeader(payload) {
		u.ch.quic = true
		e.onQUICClient(u, payload)
	}
	if src == u.client {
		u.ch.out += int64(n)
		u.ch.pktsOut++
		if n == 32 {
			u.ch.udp32Out++
		}
		if u.server.Port() == 53 && !looksDNS(payload) {
			u.ch.udpNonDNS++
		}
		if u.burstBytes > 0 && ts.Sub(u.last) > e.cfg.BurstGap {
			u.ch.addBurst(e, u.burstStart, u.burstBytes)
			u.burstBytes = 0
		}
		if u.burstBytes == 0 {
			u.burstStart = ts
		}
		u.burstBytes += int64(n)
		u.last = ts
	} else {
		u.ch.in += int64(n)
		u.ch.pktsIn++
		if n == 32 {
			u.ch.udp32In++
		}
		if u.inBurstBytes > 0 && ts.Sub(u.inLast) > e.cfg.BurstGap {
			u.ch.addInBurst(e, u.inBurstBytes)
			u.inBurstBytes = 0
		}
		u.inBurstBytes += int64(n)
		u.inLast = ts
	}
}

func (u *udpFlow) flush(e *Engine) {
	if len(e.sigma) > 0 {
		e.sigmaConn(u.client, u.server, "udp", "", u.ch.first, u.ch.firstFrame)
	}
	if u.burstBytes > 0 {
		u.ch.addBurst(e, u.burstStart, u.burstBytes)
		u.burstBytes = 0
	}
	if u.inBurstBytes > 0 {
		u.ch.addInBurst(e, u.inBurstBytes)
		u.inBurstBytes = 0
	}
}

// --------------------------------------------------------- reassembly glue

type protoHalf interface {
	feed(data []byte, ts time.Time, frame int64)
	gap()
	close(ts time.Time)
}

type streamFactory struct{ e *Engine }

func endpointAddrPort(n, t gopacket.Endpoint) netip.AddrPort {
	a, _ := netip.AddrFromSlice(n.Raw())
	raw := t.Raw()
	var port uint16
	if len(raw) == 2 {
		port = uint16(raw[0])<<8 | uint16(raw[1])
	}
	return netip.AddrPortFrom(a.Unmap(), port)
}

func (f *streamFactory) New(netFlow, tcpFlow gopacket.Flow, _ *layers.TCP, _ reassembly.AssemblerContext) reassembly.Stream {
	src := endpointAddrPort(netFlow.Src(), tcpFlow.Src())
	dst := endpointAddrPort(netFlow.Dst(), tcpFlow.Dst())
	return &tcpStream{e: f.e, conn: f.e.tcp[mkKey(src, dst)], firstSrc: src, firstDst: dst}
}

type tcpStream struct {
	e                  *Engine
	conn               *tcpConn
	firstSrc, firstDst netip.AddrPort
}

func (s *tcpStream) Accept(_ *layers.TCP, _ gopacket.CaptureInfo, _ reassembly.TCPFlowDirection, _ reassembly.Sequence, start *bool, _ reassembly.AssemblerContext) bool {
	*start = true // accept streams whose handshake predates the capture
	return true
}

func (s *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	if s.conn == nil {
		return
	}
	dir, _, _, skip := sg.Info()
	src := s.firstSrc
	if dir == reassembly.TCPDirServerToClient {
		src = s.firstDst
	}
	idx := 1
	if src == s.conn.client {
		idx = 0
	}
	n, _ := sg.Lengths()
	if skip != 0 && s.conn.halves[idx] != nil {
		s.conn.halves[idx].gap()
	}
	if n == 0 {
		return
	}
	data := sg.Fetch(n)
	ts := sg.CaptureInfo(0).Timestamp
	var frame int64
	if pc, ok := ac.(*pktCtx); ok {
		frame = pc.frame
	}
	if !s.conn.sniffed {
		s.sniff(data, idx == 0)
	}
	if h := s.conn.halves[idx]; h != nil {
		h.feed(data, ts, frame)
	}
}

func (s *tcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	var ts time.Time // the library sometimes passes a nil context here
	if ac != nil {
		ts = ac.GetCaptureInfo().Timestamp
	} else if s.conn != nil {
		ts = s.conn.last
	}
	if s.conn != nil && s.conn.closed {
		for _, h := range s.conn.halves {
			if h != nil {
				h.close(ts)
			}
		}
		if compactClosed {
			s.conn.compact()
		}
	}
	return true
}

// compactClosed releases parser state when a closed connection's
// reassembly completes (v9c 3.3); a var so tests can compare.
var compactClosed = true

// compact keeps only what scoring and reporting read after a connection
// is done — addresses, times, byte counts and burst state, frames, the
// pending Sigma events — and drops the protocol parsers, their buffers and
// the per-connection TLS handshake record (already rolled up into the
// channel). finishConn still runs at the end for the final burst.
func (c *tcpConn) compact() {
	c.compacted = true
	c.halves = [2]protoHalf{}
	c.tls = nil
	c.tunTLS = [2]*tlsHalf{}
	c.pendingMethods = nil
	c.lastHost, c.connectTarget = "", ""
}

var httpPorts = map[uint16]bool{80: true, 8080: true, 8000: true, 8008: true, 8888: true, 9090: true, 3128: true, 81: true, 591: true}

func (s *tcpStream) sniff(data []byte, fromClient bool) {
	c := s.conn
	c.sniffed = true
	port := c.server.Port()
	switch {
	case fromClient && looksLikeRequest(data) && len(data) >= 4, !fromClient && len(data) >= 7 && looksLikeResponse(data):
		c.proto = "http"
	case port == 445 || port == 139 || len(data) >= 8 && data[0] == 0 && isSMBMagic(data[4:]):
		c.proto = "smb"
	case port == 53:
		c.proto = "dns"
	case port == 389 || port == 3268 || fromClient && looksLDAP(data):
		c.proto = "ldap"
	case looksDCE(data, fromClient):
		c.proto = "dcerpc" // by PDU header, not port: EPM on 135 and the dynamic ports it hands out
	case len(data) >= 3 && data[0] == 0x16 && data[1] == 0x03:
		c.proto = "tls"
	case httpPorts[port]:
		c.proto = "http" // mid-stream start: the parser will resync
	default:
		c.proto = "other"
	}
	switch c.proto {
	case "http":
		c.halves[0], c.halves[1] = newHTTPHalf(s.e, c, true), newHTTPHalf(s.e, c, false)
	case "smb":
		st := newSMBState(s.e, c)
		c.halves[0], c.halves[1] = &smbHalf{st: st, client: true}, &smbHalf{st: st}
	case "dns":
		c.halves[0], c.halves[1] = &dnsTCPHalf{e: s.e, c: c, client: true}, &dnsTCPHalf{e: s.e, c: c}
	case "tls":
		c.halves[0], c.halves[1] = &tlsHalf{e: s.e, c: c, client: true}, &tlsHalf{e: s.e, c: c}
	case "ldap":
		ls := s.e.newLDAPSession(c)
		c.halves[0], c.halves[1] = &ldapHalf{e: s.e, s: ls, client: true}, &ldapHalf{e: s.e, s: ls}
	case "dcerpc":
		dc := s.e.newDCEConn(c)
		c.halves[0], c.halves[1] = &dceHalf{dc: dc, client: true}, &dceHalf{dc: dc}
	default:
		c.halves[0], c.halves[1] = &rawHalf{e: s.e, c: c, client: true}, &rawHalf{e: s.e, c: c}
	}
}

// parseSNI pulls server_name out of a TLS ClientHello record (best effort).
func parseSNI(b []byte) string {
	hs, _ := tlsHandshakeBytes(b)
	if len(hs) < 4 || hs[0] != 1 {
		return ""
	}
	l := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+l {
		return ""
	}
	h, ok := parseClientHello(hs[4 : 4+l])
	if !ok {
		return ""
	}
	return h.sni
}
