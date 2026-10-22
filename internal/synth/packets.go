// Package synth builds deterministic synthetic captures: packet primitives
// (Ethernet/IPv4/TCP/UDP, DNS, TLS records, HTTP/1.1, SMB2) and, in
// scenario.go, declarative traffic scenarios that write a pcap plus a
// labels manifest in the `c2parser eval` format (v9 rev 2 Phase 1.1).
//
// Synthetic traffic tests c2parser against our own model of C2. It catches
// regressions and robustness problems; it cannot set thresholds or claim
// real-world accuracy. Fixtures carry shape labels (polarity, framing,
// residue), never framework names.
package synth

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"c2parser/internal/pcapio"
)

// Builder writes packets to a classic pcap or a pcapng.
type Builder struct {
	pcap  *pcapio.Writer
	ng    *pcapio.NGWriter
	ngIf  uint32
	Snap  int // > 0 truncates stored packets to Snap bytes (orig_len kept)
	Count int // packets written

	buffered bool
	pend     []pending
}

type pending struct {
	ts   time.Time
	data []byte
	orig int
}

// Buffer holds packets in memory until Flush, which writes them in
// timestamp order (stable, so same-time packets keep write order). Use it
// when several streams are generated one after another.
func (b *Builder) Buffer() { b.buffered = true }

// Flush writes buffered packets sorted by time.
func (b *Builder) Flush() error {
	sort.SliceStable(b.pend, func(i, j int) bool { return b.pend[i].ts.Before(b.pend[j].ts) })
	for _, p := range b.pend {
		if err := b.emit(p.ts, p.data, p.orig); err != nil {
			return err
		}
	}
	b.pend = nil
	return nil
}

func (b *Builder) emit(ts time.Time, data []byte, orig int) error {
	if b.ng != nil {
		return b.ng.WritePacket(b.ngIf, ts, data, orig)
	}
	return b.pcap.WritePacketOrig(ts, data, orig)
}

// NewPcap starts a classic nanosecond pcap.
func NewPcap(w io.Writer) (*Builder, error) {
	pw, err := pcapio.NewWriter(w, layers.LinkTypeEthernet)
	if err != nil {
		return nil, err
	}
	return &Builder{pcap: pw}, nil
}

// NewPcapNG starts a pcapng with one Ethernet interface at 10^-tsresol s.
func NewPcapNG(w io.Writer, tsresol uint8) (*Builder, error) {
	nw, err := pcapio.NewNGWriter(w)
	if err != nil {
		return nil, err
	}
	id, err := nw.AddInterface(layers.LinkTypeEthernet, 262144, tsresol)
	if err != nil {
		return nil, err
	}
	return &Builder{ng: nw, ngIf: id}, nil
}

// Eth is the fixed Ethernet header used for every packet.
func Eth() *layers.Ethernet {
	return &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
}

// IP4 builds an IPv4 header.
func IP4(src, dst string, proto layers.IPProtocol) *layers.IPv4 {
	return &layers.IPv4{Version: 4, TTL: 64, Protocol: proto, SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4()}
}

// Write serialises layers (lengths and checksums fixed) as one packet.
func (b *Builder) Write(ts time.Time, ls ...gopacket.SerializableLayer) error {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		return err
	}
	data := buf.Bytes()
	orig := len(data)
	if b.Snap > 0 && len(data) > b.Snap {
		data = data[:b.Snap]
	}
	b.Count++
	if b.buffered {
		b.pend = append(b.pend, pending{ts, append([]byte(nil), data...), orig})
		return nil
	}
	return b.emit(ts, data, orig)
}

// UDP writes one datagram.
func (b *Builder) UDP(ts time.Time, src string, sport uint16, dst string, dport uint16, payload gopacket.SerializableLayer) error {
	ip := IP4(src, dst, layers.IPProtocolUDP)
	u := &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}
	u.SetNetworkLayerForChecksum(ip)
	return b.Write(ts, Eth(), ip, u, payload)
}

// DNSQuery writes a recursive query from client to resolver.
func (b *Builder) DNSQuery(ts time.Time, client, resolver, name string, qt layers.DNSType, id uint16) error {
	return b.UDP(ts, client, 50000+id%1000, resolver, 53, &layers.DNS{ID: id, RD: true,
		Questions: []layers.DNSQuestion{{Name: []byte(name), Type: qt, Class: layers.DNSClassIN}}})
}

// DNSResp writes the matching response.
func (b *Builder) DNSResp(ts time.Time, client, resolver, name string, qt layers.DNSType, id uint16, rcode layers.DNSResponseCode, ans []layers.DNSResourceRecord) error {
	return b.UDP(ts, resolver, 53, client, 50000+id%1000, &layers.DNS{ID: id, QR: true, RD: true, RA: true, ResponseCode: rcode,
		Questions: []layers.DNSQuestion{{Name: []byte(name), Type: qt, Class: layers.DNSClassIN}}, Answers: ans})
}

// TCP is one TCP connection being written (handshake already sent).
type TCP struct {
	b            *Builder
	Cli, Srv     string
	CPort, SPort uint16
	cseq, sseq   uint32
	Retransmit   bool        // duplicate the next data segment
	Drop         func() bool // if set and true, a data segment is lost (seq still advances)
	Dropped      int
	Err          error
}

// TCP opens a connection with a three-way handshake at ts.
func (b *Builder) TCP(ts time.Time, cli string, cport uint16, srv string, sport uint16) *TCP {
	return b.TCPWithISN(ts, cli, cport, srv, sport, 1000, 9000)
}

// TCPWithISN opens a TCP connection with explicit initial sequence numbers.
// This is intended for deterministic synthetic fixtures, including tuple
// reuse where the assembler's old sequence high-water mark is under test.
func (b *Builder) TCPWithISN(ts time.Time, cli string, cport uint16, srv string, sport uint16, clientISN, serverISN uint32) *TCP {
	t := &TCP{b: b, Cli: cli, Srv: srv, CPort: cport, SPort: sport, cseq: clientISN, sseq: serverISN}
	t.Seg(ts, true, nil, true, false, false)
	t.Seg(ts.Add(time.Millisecond), false, nil, true, true, false)
	t.Seg(ts.Add(2*time.Millisecond), true, nil, false, true, false)
	return t
}

// Seg writes one segment.
func (t *TCP) Seg(ts time.Time, fromClient bool, data []byte, syn, ack, fin bool) {
	src, dst, sp, dp := t.Cli, t.Srv, t.CPort, t.SPort
	seq, ackn := &t.cseq, t.sseq
	if !fromClient {
		src, dst, sp, dp = t.Srv, t.Cli, t.SPort, t.CPort
		seq, ackn = &t.sseq, t.cseq
	}
	ip := IP4(src, dst, layers.IPProtocolTCP)
	tc := &layers.TCP{SrcPort: layers.TCPPort(sp), DstPort: layers.TCPPort(dp), Seq: *seq, Ack: ackn, SYN: syn, ACK: ack, FIN: fin, PSH: len(data) > 0, Window: 65535}
	tc.SetNetworkLayerForChecksum(ip)
	if len(data) > 0 && t.Drop != nil && t.Drop() {
		t.Dropped++
	} else if err := t.b.Write(ts, Eth(), ip, tc, gopacket.Payload(data)); err != nil && t.Err == nil {
		t.Err = err
	}
	if t.Retransmit && len(data) > 0 {
		_ = t.b.Write(ts.Add(time.Millisecond), Eth(), ip, tc, gopacket.Payload(data)) // exact duplicate
		t.Retransmit = false
	}
	*seq += uint32(len(data))
	if syn || fin {
		*seq++
	}
}

// Send splits data into segments of at most mss bytes, 200 µs apart, and
// returns the time after the last one.
func (t *TCP) Send(ts time.Time, fromClient bool, data []byte, mss int) time.Time {
	for len(data) > 0 {
		n := min(mss, len(data))
		t.Seg(ts, fromClient, data[:n], false, true, false)
		data = data[n:]
		ts = ts.Add(200 * time.Microsecond)
	}
	return ts
}

// Close writes FIN from both sides.
func (t *TCP) Close(ts time.Time) {
	t.Seg(ts, true, nil, false, true, true)
	t.Seg(ts.Add(time.Millisecond), false, nil, false, true, true)
}

// RandBytes returns n bytes from r.
func RandBytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.IntN(256))
	}
	return b
}

// ClientHello builds a TLS 1.3-style ClientHello record (TLS 1.2 record
// version), with SNI and ALPN when given.
func ClientHello(sni string, alpn []string) []byte { return ClientHelloV(sni, alpn, "1.3") }

// ClientHelloV builds a ClientHello offering TLS 1.3 (version "1.3":
// supported_versions and TLS 1.3 suites) or only TLS 1.2 ("1.2": ECDHE-GCM
// suites, no supported_versions).
func ClientHelloV(sni string, alpn []string, version string) []byte {
	tls12 := version == "1.2"
	var ext []byte
	add := func(typ uint16, data []byte) {
		ext = binary.BigEndian.AppendUint16(ext, typ)
		ext = binary.BigEndian.AppendUint16(ext, uint16(len(data)))
		ext = append(ext, data...)
	}
	if sni != "" {
		var d []byte
		d = binary.BigEndian.AppendUint16(d, uint16(len(sni)+3))
		d = append(d, 0)
		d = binary.BigEndian.AppendUint16(d, uint16(len(sni)))
		add(0, append(d, sni...))
	}
	add(10, []byte{0, 4, 0, 0x1d, 0, 0x17})       // groups x25519, secp256r1
	add(13, []byte{0, 4, 0x04, 0x03, 0x08, 0x04}) // sig algs
	if len(alpn) > 0 {
		var l []byte
		for _, p := range alpn {
			l = append(l, byte(len(p)))
			l = append(l, p...)
		}
		add(16, append(binary.BigEndian.AppendUint16(nil, uint16(len(l))), l...))
	}
	if !tls12 {
		add(43, []byte{4, 0x03, 0x04, 0x03, 0x03}) // supported_versions 1.3, 1.2
	}
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	if tls12 {
		body = append(body, 0, 4, 0xc0, 0x2f, 0xc0, 0x30)
	} else {
		body = append(body, 0, 4, 0x13, 0x01, 0x13, 0x02)
	}
	body = append(body, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

// AppData is a TLS application-data record carrying payload.
func AppData(payload []byte) []byte {
	n := len(payload)
	return append([]byte{0x17, 3, 3, byte(n >> 8), byte(n)}, payload...)
}

// HTTPReq builds an HTTP/1.1 request (Content-Length added for bodies and
// every POST).
func HTTPReq(method, uri string, hdrs []string, body string) []byte {
	h := method + " " + uri + " HTTP/1.1\r\n" + strings.Join(hdrs, "\r\n") + "\r\n"
	if body != "" || method == "POST" {
		h += fmt.Sprintf("Content-Length: %d\r\n", len(body))
	}
	return []byte(h + "\r\n" + body)
}

// HTTPResp builds an HTTP/1.x response with Content-Length.
func HTTPResp(statusLine string, hdrs []string, body string) []byte {
	h := statusLine + "\r\n" + strings.Join(hdrs, "\r\n") + "\r\n"
	h += fmt.Sprintf("Content-Length: %d\r\n", len(body))
	return []byte(h + "\r\n" + body)
}

// SMB2Hdr is a 64-byte SMB2 header.
func SMB2Hdr(cmd uint16, resp bool, mid uint64, tree uint32, status uint32) []byte {
	h := make([]byte, 64)
	copy(h, "\xfeSMB")
	binary.LittleEndian.PutUint16(h[4:], 64)
	binary.LittleEndian.PutUint32(h[8:], status)
	binary.LittleEndian.PutUint16(h[12:], cmd)
	if resp {
		binary.LittleEndian.PutUint32(h[16:], 1)
	}
	binary.LittleEndian.PutUint64(h[24:], mid)
	binary.LittleEndian.PutUint32(h[36:], tree)
	return h
}

// NB wraps an SMB message in a NetBIOS session header.
func NB(msg []byte) []byte {
	return append([]byte{0, byte(len(msg) >> 16), byte(len(msg) >> 8), byte(len(msg))}, msg...)
}

// U16LE encodes s as UTF-16LE.
func U16LE(s string) []byte {
	var b []byte
	for _, r := range s {
		b = binary.LittleEndian.AppendUint16(b, uint16(r))
	}
	return b
}

// SMB2 command codes used by the builders.
const (
	SMBTreeConnect = 0x03
	SMBCreate      = 0x05
	SMBRead        = 0x08
	SMBWrite       = 0x09
)

// SMBPipe is an SMB2 session on TCP/445 with one named pipe open on IPC$.
type SMBPipe struct {
	T    *TCP
	tree uint32
	fid  []byte
	mid  uint64
}

// OpenPipe connects to IPC$ and opens pipeName (requests and responses).
func (b *Builder) OpenPipe(ts time.Time, cli string, cport uint16, srv, pipeName string, fid byte) (*SMBPipe, time.Time) {
	t := b.TCP(ts, cli, cport, srv, 445)
	p := &SMBPipe{T: t, tree: 7, fid: make([]byte, 16), mid: 1}
	for i := range p.fid {
		p.fid[i] = fid
	}
	step := func(fromClient bool, msg []byte) {
		ts = ts.Add(2 * time.Millisecond)
		ts = t.Send(ts, fromClient, NB(msg), 1400)
	}
	path := U16LE(`\\` + srv + `\IPC$`)
	tc := make([]byte, 8)
	binary.LittleEndian.PutUint16(tc[0:], 9)
	binary.LittleEndian.PutUint16(tc[4:], 64+8)
	binary.LittleEndian.PutUint16(tc[6:], uint16(len(path)))
	step(true, append(append(SMB2Hdr(SMBTreeConnect, false, p.mid, 0, 0), tc...), path...))
	step(false, append(SMB2Hdr(SMBTreeConnect, true, p.mid, p.tree, 0), make([]byte, 16)...))
	p.mid++
	name := U16LE(pipeName)
	cr := make([]byte, 56)
	binary.LittleEndian.PutUint16(cr[0:], 57)
	binary.LittleEndian.PutUint16(cr[44:], 64+56)
	binary.LittleEndian.PutUint16(cr[46:], uint16(len(name)))
	step(true, append(append(SMB2Hdr(SMBCreate, false, p.mid, p.tree, 0), cr...), name...))
	crr := make([]byte, 88)
	binary.LittleEndian.PutUint16(crr[0:], 89)
	binary.LittleEndian.PutUint32(crr[4:], 1)
	copy(crr[64:80], p.fid)
	step(false, append(SMB2Hdr(SMBCreate, true, p.mid, p.tree, 0), crr...))
	p.mid++
	return p, ts
}

// Write sends one SMB2 WRITE of data to the pipe.
func (p *SMBPipe) Write(ts time.Time, data []byte) time.Time {
	wr := make([]byte, 48)
	binary.LittleEndian.PutUint16(wr[0:], 49)
	binary.LittleEndian.PutUint16(wr[2:], 64+48)
	binary.LittleEndian.PutUint32(wr[4:], uint32(len(data)))
	copy(wr[16:32], p.fid)
	msg := append(append(SMB2Hdr(SMBWrite, false, p.mid, p.tree, 0), wr...), data...)
	p.mid++
	return p.T.Send(ts, true, NB(msg), 1400)
}

// Read sends a READ request and its response carrying data.
func (p *SMBPipe) Read(ts time.Time, data []byte) time.Time {
	rd := make([]byte, 48)
	binary.LittleEndian.PutUint16(rd[0:], 49)
	copy(rd[16:32], p.fid)
	ts = p.T.Send(ts, true, NB(append(SMB2Hdr(SMBRead, false, p.mid, p.tree, 0), rd...)), 1400)
	rr := make([]byte, 16)
	binary.LittleEndian.PutUint16(rr[0:], 17)
	rr[2] = 64 + 16
	binary.LittleEndian.PutUint32(rr[4:], uint32(len(data)))
	ts = p.T.Send(ts.Add(time.Millisecond), false, NB(append(append(SMB2Hdr(SMBRead, true, p.mid, p.tree, 0), rr...), data...)), 1400)
	p.mid++
	return ts
}
