package synth

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Scenario is one declarative capture: a set of streams written into one
// pcap (or pcapng). Every byte is a function of (scenario, seed).
type Scenario struct {
	Name    string    `yaml:"name"`
	Seed    uint64    `yaml:"seed"`
	Start   time.Time `yaml:"start"`   // default 2024-03-25T12:00:00Z
	Format  string    `yaml:"format"`  // pcap (default) | pcapng
	TSResol uint8     `yaml:"tsresol"` // pcapng: 10^-n s (default 6)
	Snaplen int       `yaml:"snaplen"` // > 0 truncates stored packets (orig_len kept)
	Streams []Stream  `yaml:"streams"`
	// Expect holds optional score gates for tests ("v1" / "v2" → bounds).
	Expect []Expect `yaml:"expect"`
}

// Stream is one traffic stream: a transport, a topology, a schedule and
// message content.
type Stream struct {
	Label     string    `yaml:"label"` // c2 | benign
	Shape     string    `yaml:"shape"` // free shape label, e.g. "polarity=shortening,residue=4"
	Transport string    `yaml:"transport"`
	Server    string    `yaml:"server"` // server IP (dns: resolver IP)
	Port      uint16    `yaml:"port"`   // default per transport
	Name      string    `yaml:"name"`   // SNI / Host / DNS zone / pipe name
	Topology  Topology  `yaml:"topology"`
	Timing    Timing    `yaml:"timing"`
	Artifacts Artifacts `yaml:"artifacts"`
	Content   Content   `yaml:"content"`
}

// Topology places clients and servers.
type Topology struct {
	Clients []string `yaml:"clients"`
	// Fleet adds N clients counting up from Base (10.50.0.11 → .11, .12 …).
	Fleet *Fleet `yaml:"fleet"`
	// NAT rewrites every client to this address (distinct source ports).
	NAT string `yaml:"nat"`
	// Redirectors spreads check-ins over several server IPs; the name (SNI /
	// Host) stays the same, so the K1 name key sees one destination.
	Redirectors *Redirectors `yaml:"redirectors"`
	// Proxy "ip:port": HTTPS goes through an HTTP CONNECT proxy.
	Proxy string `yaml:"proxy"`
	// Stagger is the client start offset step in seconds (default: a random
	// offset within one sleep per client).
	Stagger float64 `yaml:"stagger"`
}

// Fleet is N consecutive client addresses.
type Fleet struct {
	Base string `yaml:"base"`
	N    int    `yaml:"n"`
}

// Redirectors is a pool of server IPs.
type Redirectors struct {
	Mode string   `yaml:"mode"` // round-robin | random | cdn
	IPs  []string `yaml:"ips"`
}

// Expect is a score gate for one stream's finding (tests only).
type Expect struct {
	Engine string  `yaml:"engine"` // v1 | v2
	Server string  `yaml:"server"` // finding title contains this
	Client string  `yaml:"client"`
	Min    float64 `yaml:"min"`
	Max    float64 `yaml:"max"`
	// Evidence, when set, must appear in the finding's evidence lines.
	Evidence string `yaml:"evidence"`
	Note     string `yaml:"note"`
	// Category of the finding to check: "" (C2 channel), recon, lateral
	// or any.
	Category string `yaml:"category"`
}

// Transports supported by the generator.
var Transports = []string{"http-new-conn", "http-keepalive", "https-new-conn", "https-keepalive",
	"dns", "websocket-poll", "websocket-push", "smb-pipe", "tcp-pivot", "udp", "quic", "ldap", "dcerpc-tcp"}

// ManifestEntry is one capture row in the `c2parser eval` manifest format
// (field names match internal/eval.Capture), plus generator provenance.
type ManifestEntry struct {
	Path      string     `yaml:"path"`
	Licence   string     `yaml:"licence"`
	Framework string     `yaml:"framework"` // shape label "synth:<scenario>" — never a framework name
	Transport string     `yaml:"transport"`
	Sleep     float64    `yaml:"sleep"`
	Jitter    float64    `yaml:"jitter"` // percent, as in eval manifests
	Polarity  string     `yaml:"polarity"`
	Tasking   string     `yaml:"tasking"`
	Benign    bool       `yaml:"benign"`
	C2        []Endpoint `yaml:"c2,omitempty"`
	// provenance (ignored by eval)
	Scenario string   `yaml:"scenario"`
	Seed     uint64   `yaml:"seed"`
	Shapes   []string `yaml:"shapes,omitempty"`
	SHA256   string   `yaml:"sha256"`
	// Wire are the C2 streams' client and server IPs as they appear in
	// packets (redirector and proxy IPs, not names): for Zeek label files.
	Wire []Endpoint `yaml:"-"`
}

// Endpoint is a C2 label: client plus server IP or name.
type Endpoint struct {
	Client string `yaml:"client"`
	Server string `yaml:"server"`
}

// Manifest is the eval-format manifest.
type Manifest struct {
	Captures []ManifestEntry `yaml:"captures"`
}

// LoadScenario reads a scenario YAML file.
func LoadScenario(path string) (*Scenario, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseScenario(b)
}

// ParseScenario parses scenario YAML (strict: unknown keys are errors).
func ParseScenario(b []byte) (*Scenario, error) {
	var sc Scenario
	if err := safeUnmarshal(b, &sc, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("scenario: %w", err)
	}
	return &sc, sc.Validate()
}

// Validate checks a scenario.
func (sc *Scenario) Validate() error {
	if sc.Name == "" {
		return fmt.Errorf("scenario: name is required")
	}
	if len(sc.Streams) == 0 {
		return fmt.Errorf("scenario %s: no streams", sc.Name)
	}
	for i, st := range sc.Streams {
		where := fmt.Sprintf("scenario %s stream %d", sc.Name, i)
		if st.Label != "c2" && st.Label != "benign" {
			return fmt.Errorf("%s: label must be c2 or benign", where)
		}
		if !containsS(Transports, st.Transport) {
			return fmt.Errorf("%s: unknown transport %q", where, st.Transport)
		}
		if _, err := netip.ParseAddr(st.Server); err != nil {
			return fmt.Errorf("%s: server: %w", where, err)
		}
		if len(st.clients()) == 0 {
			return fmt.Errorf("%s: no clients", where)
		}
		if err := st.Timing.Validate(); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		if _, err := newKeyed(st.Content, rand.New(rand.NewPCG(0, 0))); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		if st.Transport == "ldap" {
			if _, err := LDAPPreset(st.Content.Preset, "", ""); err != nil {
				return fmt.Errorf("%s: %w", where, err)
			}
		}
		if s := st.Content.SASL; s != "" && (st.Transport != "ldap" || s != "ntlm" && s != "krb") {
			return fmt.Errorf("%s: sasl %q: ldap only, ntlm or krb", where, s)
		}
		if st.Transport == "dcerpc-tcp" && st.Content.Preset != "wmi-exec" && st.Content.Preset != "epm-drsuapi" {
			return fmt.Errorf("%s: dcerpc-tcp preset %q: want wmi-exec or epm-drsuapi", where, st.Content.Preset)
		}
		if st.Transport == "quic" && st.Name == "" {
			return fmt.Errorf("%s: quic needs an SNI name", where)
		}
		if st.Transport == "dns" && st.Name == "" {
			return fmt.Errorf("%s: dns needs a zone name", where)
		}
		if lower := strings.ToLower(st.Shape + " " + sc.Name); containsAny(lower, frameworkNames) {
			return fmt.Errorf("%s: shape labels only — no framework names (Phase 1.3 corpus rule)", where)
		}
	}
	return nil
}

// frameworkNames may not appear in synthetic labels: synthetic traffic is
// our model of a shape, not framework ground truth.
var frameworkNames = []string{"cobalt", "sliver", "mythic", "havoc", "merlin", "empire", "covenant", "poshc2", "meterpreter", "brute ratel", "bruteratel"}

func containsAny(s string, subs []string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func containsS(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func (st Stream) clients() []string {
	out := append([]string{}, st.Topology.Clients...)
	if f := st.Topology.Fleet; f != nil {
		a, err := netip.ParseAddr(f.Base)
		if err == nil {
			for i := 0; i < f.N; i++ {
				out = append(out, a.String())
				a = a.Next()
			}
		}
	}
	return out
}

// seedFor derives a stream/client RNG seed from the scenario seed.
func seedFor(seed uint64, parts ...string) (uint64, uint64) {
	h := sha256.New()
	_ = binary.Write(h, binary.BigEndian, seed)
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	s := h.Sum(nil)
	return binary.BigEndian.Uint64(s[:8]), binary.BigEndian.Uint64(s[8:16])
}

// Generate writes the scenario as a capture to w and returns its manifest
// row (Path and SHA256 left for the caller, see WriteFile).
func Generate(sc *Scenario, w io.Writer) (*ManifestEntry, error) {
	if err := sc.Validate(); err != nil {
		return nil, err
	}
	start := sc.Start
	if start.IsZero() {
		start = time.Date(2024, 3, 25, 12, 0, 0, 0, time.UTC)
	}
	var b *Builder
	var err error
	if sc.Format == "pcapng" {
		res := sc.TSResol
		if res == 0 {
			res = 6
		}
		b, err = NewPcapNG(w, res)
	} else {
		b, err = NewPcap(w)
	}
	if err != nil {
		return nil, err
	}
	b.Snap = sc.Snaplen
	b.Buffer()
	me := &ManifestEntry{Licence: "own", Framework: "synth:" + sc.Name, Scenario: sc.Name, Seed: sc.Seed, Tasking: "no", Benign: true}
	nextPort := map[string]uint16{}
	port := func(client string) uint16 {
		p, ok := nextPort[client]
		if !ok {
			s1, _ := seedFor(sc.Seed, "port", client)
			p = 49152 + uint16(s1%4000)
		}
		nextPort[client] = p + 1
		return p
	}
	for i, st := range sc.Streams {
		if st.Shape != "" {
			me.Shapes = append(me.Shapes, st.Shape)
		}
		if st.Label == "c2" {
			if me.Benign { // first C2 stream sets the cell
				me.Benign = false
				me.Transport, me.Sleep, me.Jitter, me.Polarity = st.Transport, st.Timing.Sleep, st.Timing.Jitter*100, st.Timing.Polarity()
				if st.Artifacts.Tasking != nil {
					me.Tasking = "yes"
				}
			}
		}
		for ci, client := range st.clients() {
			s1, s2 := seedFor(sc.Seed, fmt.Sprint(i), client)
			r := rand.New(rand.NewPCG(s1, s2))
			wire := client
			if st.Topology.NAT != "" {
				wire = st.Topology.NAT
			}
			off := st.Timing.Sleep * r.Float64()
			if st.Topology.Stagger > 0 {
				off = st.Topology.Stagger * float64(ci)
			}
			cs := start.Add(time.Duration(off * float64(time.Second)))
			evs := Schedule(cs, st.Timing, st.Artifacts, r)
			if err := writeStream(b, st, wire, evs, r, func() uint16 { return port(wire) }); err != nil {
				return nil, fmt.Errorf("stream %d: %w", i, err)
			}
			if st.Label == "c2" {
				srv := st.Server
				if st.Name != "" && (st.Transport == "dns" || st.Topology.Redirectors != nil || st.Topology.Proxy != "") {
					srv = st.Name
				}
				me.C2 = appendEP(me.C2, Endpoint{Client: wire, Server: srv})
				for _, ip := range wireIPs(st) {
					me.Wire = appendEP(me.Wire, Endpoint{Client: wire, Server: ip})
				}
			}
		}
	}
	if err := b.Flush(); err != nil {
		return nil, err
	}
	return me, nil
}

func appendEP(eps []Endpoint, e Endpoint) []Endpoint {
	for _, x := range eps {
		if x == e {
			return eps
		}
	}
	return append(eps, e)
}

// WriteFile generates sc into dir/<name>.pcap[ng] and returns the manifest
// row with a relative path and the file's SHA-256.
func WriteFile(sc *Scenario, dir string) (*ManifestEntry, error) {
	var buf bytes.Buffer
	me, err := Generate(sc, &buf)
	if err != nil {
		return nil, err
	}
	ext := ".pcap"
	if sc.Format == "pcapng" {
		ext = ".pcapng"
	}
	name := sc.Name + ext
	if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o644); err != nil {
		return nil, err
	}
	me.Path = name
	me.SHA256 = fmt.Sprintf("%x", sha256.Sum256(buf.Bytes()))
	return me, nil
}

// WriteManifest writes an eval-format manifest.
func WriteManifest(path string, rows []ManifestEntry) error {
	sort.Slice(rows, func(i, j int) bool { return rows[i].Path < rows[j].Path })
	b, err := yaml.Marshal(Manifest{Captures: rows})
	if err != nil {
		return err
	}
	hdr := "# Generated by c2parser-synthgen. Synthetic shapes only: tests the program\n# against our own model of C2; cannot set thresholds (docs/corpus.md).\n"
	return os.WriteFile(path, append([]byte(hdr), b...), 0o644)
}

// ---------------------------------------------------------------- writers

type conn struct {
	t       *TCP
	pipe    *SMBPipe
	tlsDone bool
}

func writeStream(b *Builder, st Stream, client string, evs []Event, r *rand.Rand, port func() uint16) error {
	k, err := newKeyed(st.Content, r)
	if err != nil {
		return err
	}
	servers := []string{st.Server}
	if rd := st.Topology.Redirectors; rd != nil && len(rd.IPs) > 0 {
		servers = rd.IPs
	}
	pick := func(i int) string {
		rd := st.Topology.Redirectors
		switch {
		case rd == nil || len(servers) == 1:
			return servers[0]
		case rd.Mode == "round-robin":
			return servers[i%len(servers)]
		default: // random, cdn
			return servers[r.IntN(len(servers))]
		}
	}
	dport := st.Port
	if dport == 0 {
		dport = map[string]uint16{"http-new-conn": 80, "http-keepalive": 80, "https-new-conn": 443, "https-keepalive": 443,
			"dns": 53, "websocket-poll": 80, "websocket-push": 80, "smb-pipe": 445, "tcp-pivot": 4444, "udp": 51820, "quic": 443, "ldap": 389, "dcerpc-tcp": 49712}[st.Transport]
	}
	keep := map[string]*conn{}
	var last time.Time
	dnsID := uint16(r.IntN(30000))
	var udpSport uint16
	for i, ev := range evs {
		ts := ev.At
		srv := pick(i)
		respN := k.c.Resp.Draw(r)
		if ev.Tasking && st.Artifacts.Tasking != nil && st.Artifacts.Tasking.RespBytes > 0 {
			respN = st.Artifacts.Tasking.RespBytes
		}
		poll := k.body(r, k.c.Poll.Draw(r))
		resp := k.body(r, respN)
		switch st.Transport {
		case "quic": // one QUIC connection per check-in: client Initial(s) + short-header traffic
			last = b.QUICSession(ts, client, port(), srv, dport, QUICv1, RandBytes(r, 8), st.Name, 1+r.IntN(2), 1+r.IntN(3))
			continue
		case "ldap": // one LDAP session per event to the DC
			host := fmt.Sprintf("WS%d", r.IntN(900)+100)
			qs, err := LDAPPreset(k.c.Preset, "DC=corp,DC=example", host)
			if err != nil {
				return err
			}
			last = b.LDAPSessionSASL(ts, client, port(), srv, k.c.SASL, qs)
			continue
		case "dcerpc-tcp":
			var err error
			if last, err = b.DCERPCSession(ts, client, port, srv, dport, k.c.Preset); err != nil {
				return err
			}
			continue
		case "udp":
			if udpSport == 0 { // one flow per client, like a tunnel endpoint
				udpSport = 51820
				if dport == 53 {
					udpSport = port()
				}
			}
			sport := udpSport
			if err := b.UDP(ts, client, sport, srv, dport, gopacket.Payload(poll)); err != nil {
				return err
			}
			if len(resp) > 0 {
				if err := b.UDP(ts.Add(30*time.Millisecond), srv, dport, client, sport, gopacket.Payload(resp)); err != nil {
					return err
				}
			}
			last = ts
			continue
		case "dns":
			dnsID++
			name := dnsName(string(poll), st.Name)
			qt := map[string]layers.DNSType{"": layers.DNSTypeA, "A": layers.DNSTypeA, "TXT": layers.DNSTypeTXT, "AAAA": layers.DNSTypeAAAA}[strings.ToUpper(k.c.QType)]
			if qt == 0 {
				return fmt.Errorf("dns qtype %q", k.c.QType)
			}
			if err := b.DNSQuery(ts, client, srv, name, qt, dnsID); err != nil {
				return err
			}
			rr := layers.DNSResourceRecord{Name: []byte(name), Type: qt, Class: layers.DNSClassIN, TTL: 1}
			switch qt {
			case layers.DNSTypeTXT:
				txt := resp
				if len(txt) > 255 {
					txt = txt[:255]
				}
				rr.TXTs = [][]byte{txt}
			case layers.DNSTypeAAAA:
				rr.IP = append([]byte{0xfd, 0}, RandBytes(r, 14)...)
			default:
				rr.IP = []byte{10, byte(r.IntN(256)), byte(r.IntN(256)), byte(r.IntN(256))}
			}
			if err := b.DNSResp(ts.Add(20*time.Millisecond), client, srv, name, qt, dnsID, layers.DNSResponseCodeNoErr, []layers.DNSResourceRecord{rr}); err != nil {
				return err
			}
			last = ts
			continue
		}
		newConn := strings.HasSuffix(st.Transport, "new-conn")
		c := keep[srv]
		if c == nil || newConn {
			c = &conn{}
			target, tport := srv, dport
			if st.Topology.Proxy != "" {
				ap, err := netip.ParseAddrPort(st.Topology.Proxy)
				if err != nil {
					return fmt.Errorf("proxy: %w", err)
				}
				target, tport = ap.Addr().String(), ap.Port()
			}
			if st.Transport == "smb-pipe" {
				pn := st.Name
				if pn == "" {
					pn = "pipe" + fmt.Sprint(r.IntN(1000))
				}
				c.pipe, ts = b.OpenPipe(ts.Add(-50*time.Millisecond), client, port(), target, pn, byte(1+r.IntN(250)))
				c.t = c.pipe.T
			} else {
				c.t = b.TCP(ts.Add(-50*time.Millisecond), client, port(), target, tport)
				ts = ts.Add(-47 * time.Millisecond)
			}
			if st.Topology.Proxy != "" && strings.HasPrefix(st.Transport, "https") {
				host := st.Name
				if host == "" {
					host = srv
				}
				ts = c.t.Send(ts, true, HTTPReq("CONNECT", host+":443", []string{"Host: " + host + ":443"}, ""), 1400)
				ts = c.t.Send(ts.Add(5*time.Millisecond), false, []byte("HTTP/1.1 200 Connection established\r\n\r\n"), 1400)
			}
			if strings.HasPrefix(st.Transport, "websocket") {
				ts = c.t.Send(ts, true, HTTPReq("GET", uriOr(k.c.URI, "/ws"), append([]string{"Host: " + hostOr(st.Name, srv), "Upgrade: websocket", "Connection: Upgrade",
					"Sec-WebSocket-Key: " + b64(RandBytes(r, 16)), "Sec-WebSocket-Version: 13"}, k.c.Headers...), ""), 1400)
				ts = c.t.Send(ts.Add(10*time.Millisecond), false, []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+b64(RandBytes(r, 20))+"\r\n\r\n"), 1400)
			}
			if !newConn {
				keep[srv] = c
			}
		}
		if ts.Before(ev.At) {
			ts = ev.At
		}
		switch {
		case strings.HasPrefix(st.Transport, "https"):
			if !c.tlsDone {
				ts = c.t.Send(ts, true, ClientHelloV(st.Name, k.c.ALPN, k.c.TLS), 1400)
				ts = c.t.Send(ts.Add(20*time.Millisecond), false, AppData(RandBytes(r, 1400)), 1400)
				c.tlsDone = true
			}
			ts = c.t.Send(ts.Add(5*time.Millisecond), true, AppData(poll), 1400)
			ts = c.t.Send(ts.Add(40*time.Millisecond), false, AppData(resp), 1400)
		case strings.HasPrefix(st.Transport, "http"):
			m := k.c.Method
			if m == "" {
				m = "GET"
			}
			uri, body := uriOr(k.c.URI, "/"), string(poll)
			if m == "GET" && len(poll) > 0 {
				sep := "?"
				if strings.Contains(uri, "?") {
					sep = "&"
				}
				uri, body = uri+sep+"d="+string(poll), ""
			}
			hdrs := append([]string{"Host: " + hostOr(st.Name, srv)}, k.c.Headers...)
			ts = c.t.Send(ts, true, HTTPReq(m, uri, hdrs, body), 1400)
			ts = c.t.Send(ts.Add(40*time.Millisecond), false, HTTPResp("HTTP/1.1 200 OK", []string{"Content-Type: application/octet-stream"}, string(resp)), 1400)
		case st.Transport == "websocket-poll":
			ts = c.t.Send(ts, true, wsFrame(r, poll, true), 1400)
			ts = c.t.Send(ts.Add(40*time.Millisecond), false, wsFrame(r, resp, false), 1400)
		case st.Transport == "websocket-push":
			ts = c.t.Send(ts, false, wsFrame(r, resp, false), 1400)
		case st.Transport == "smb-pipe":
			ts = c.pipe.Write(ts, poll)
			ts = c.pipe.Read(ts.Add(5*time.Millisecond), resp)
		case st.Transport == "tcp-pivot":
			ts = c.t.Send(ts, true, Frame(k.c.Framing, poll), 1400)
			ts = c.t.Send(ts.Add(30*time.Millisecond), false, Frame(k.c.Framing, resp), 1400)
		}
		if newConn {
			c.t.Close(ts.Add(10 * time.Millisecond))
		}
		last = ts
	}
	srvs := make([]string, 0, len(keep))
	for s := range keep {
		srvs = append(srvs, s)
	}
	sort.Strings(srvs)
	for _, s := range srvs {
		keep[s].t.Close(last.Add(time.Second))
	}
	return nil
}

func uriOr(u, d string) string {
	if u == "" {
		return d
	}
	return u
}

func hostOr(h, d string) string {
	if h == "" {
		return d
	}
	return h
}

func b64(b []byte) string {
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var sb strings.Builder
	for i := 0; i+2 < len(b); i += 3 {
		v := uint(b[i])<<16 | uint(b[i+1])<<8 | uint(b[i+2])
		sb.WriteByte(a[v>>18&63])
		sb.WriteByte(a[v>>12&63])
		sb.WriteByte(a[v>>6&63])
		sb.WriteByte(a[v&63])
	}
	return sb.String()
}

// dnsName packs data into ≤ 63-byte labels under zone (max 253 bytes).
func dnsName(data, zone string) string {
	data = strings.ToLower(data)
	room := 253 - len(zone) - 1
	var labels []string
	for len(data) > 0 && room > 1 {
		n := min(63, len(data), room-1)
		labels = append(labels, data[:n])
		data = data[n:]
		room -= n + 1
	}
	return strings.Join(append(labels, zone), ".")
}

// wsFrame builds one binary WebSocket frame (client frames masked).
func wsFrame(r *rand.Rand, p []byte, masked bool) []byte {
	h := []byte{0x82}
	mbit := byte(0)
	if masked {
		mbit = 0x80
	}
	switch n := len(p); {
	case n < 126:
		h = append(h, mbit|byte(n))
	case n < 65536:
		h = append(h, mbit|126, byte(n>>8), byte(n))
	default:
		h = append(h, mbit|127)
		h = binary.BigEndian.AppendUint64(h, uint64(n))
	}
	if !masked {
		return append(h, p...)
	}
	key := RandBytes(r, 4)
	h = append(h, key...)
	for i, c := range p {
		h = append(h, c^key[i%4])
	}
	return h
}

// safeUnmarshal is yaml.Unmarshal that turns a decoder panic into an
// error (goccy/go-yaml v1.19.2 panics on some malformed input, e.g. a
// tagged mapping where a sequence is expected; found by fuzzing).
func safeUnmarshal(b []byte, v any, opts ...yaml.DecodeOption) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("yaml: malformed input (%v)", r)
		}
	}()
	return yaml.UnmarshalWithOptions(b, v, opts...)
}
