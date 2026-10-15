package engine

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	sy "c2parser/internal/synth"
)

// synth builds small, fully-controlled captures for tests. The packet
// primitives live in internal/synth; this wrapper adds t.Fatal handling.
type synth struct {
	t   *testing.T
	buf bytes.Buffer
	b   *sy.Builder
	now time.Time
}

func newSynth(t *testing.T) *synth {
	s := &synth{t: t, now: time.Date(2024, 3, 25, 12, 0, 0, 0, time.UTC)}
	b, err := sy.NewPcap(&s.buf)
	if err != nil {
		t.Fatal(err)
	}
	s.b = b
	return s
}

func (s *synth) write(ts time.Time, ls ...gopacket.SerializableLayer) {
	if err := s.b.Write(ts, ls...); err != nil {
		s.t.Fatal(err)
	}
}

func eth() *layers.Ethernet { return sy.Eth() }

func ip4(src, dst string, proto layers.IPProtocol) *layers.IPv4 { return sy.IP4(src, dst, proto) }

func (s *synth) udp(ts time.Time, src string, sport uint16, dst string, dport uint16, payload gopacket.SerializableLayer) {
	if err := s.b.UDP(ts, src, sport, dst, dport, payload); err != nil {
		s.t.Fatal(err)
	}
}

func (s *synth) dnsQuery(ts time.Time, client, resolver, name string, qt layers.DNSType, id uint16) {
	if err := s.b.DNSQuery(ts, client, resolver, name, qt, id); err != nil {
		s.t.Fatal(err)
	}
}

func (s *synth) dnsResp(ts time.Time, client, resolver, name string, qt layers.DNSType, id uint16, rcode layers.DNSResponseCode, ans []layers.DNSResourceRecord) {
	if err := s.b.DNSResp(ts, client, resolver, name, qt, id, rcode, ans); err != nil {
		s.t.Fatal(err)
	}
}

// tcpSession is the library TCP writer (handshake already sent).
type tcpSession = sy.TCP

func (s *synth) tcp(ts time.Time, cli string, cport uint16, srv string, sport uint16) *tcpSession {
	return s.b.TCP(ts, cli, cport, srv, sport)
}

func (s *synth) analyze(cfg Config) *Result {
	dir := s.t.TempDir()
	p := filepath.Join(dir, "synth.pcap")
	if err := os.WriteFile(p, s.buf.Bytes(), 0o600); err != nil {
		s.t.Fatal(err)
	}
	res, err := AnalyzeFile(p, cfg)
	if err != nil {
		s.t.Fatal(err)
	}
	return res
}

func findBy(res *Result, cat, contains string) *Finding {
	for i := range res.Findings {
		f := &res.Findings[i]
		if f.Category == cat && strings.Contains(f.Title, contains) {
			return f
		}
	}
	return nil
}

func randB(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

// ---------------------------------------------------------------- DNS

func TestDNSTunnelDGAAndBenign(t *testing.T) {
	s := newSynth(t)
	r := mrand.New(mrand.NewPCG(7, 7))
	ts := s.now
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding)
	id := uint16(1)
	// dnscat2/iodine-style tunnel: 400 TXT queries every ~1.5s carrying 30
	// random bytes each, base32 in the qname, base64 in the TXT answer.
	for i := 0; i < 400; i++ {
		ts = ts.Add(time.Duration((1.5 + 0.1*(r.Float64()*2-1)) * float64(time.Second)))
		enc := strings.ToLower(b32.EncodeToString(randB(30)))
		name := fmt.Sprintf("%s.%s.%x.t.evil-tunnel.com", enc[:24], enc[24:], i)
		s.dnsQuery(ts, "10.0.0.5", "10.0.0.53", name, layers.DNSTypeTXT, id)
		s.dnsResp(ts.Add(20*time.Millisecond), "10.0.0.5", "10.0.0.53", name, layers.DNSTypeTXT, id, layers.DNSResponseCodeNoErr,
			[]layers.DNSResourceRecord{{Name: []byte(name), Type: layers.DNSTypeTXT, Class: layers.DNSClassIN, TTL: 0,
				TXTs: [][]byte{[]byte(base64.StdEncoding.EncodeToString(randB(90)))}}})
		id++
	}
	// Benign: popular names at human-random times, plus a CDN with a few
	// hashed hostnames.
	benign := []string{"www.google.com", "outlook.office365.com", "login.microsoftonline.com", "www.bing.com", "github.com"}
	bt := s.now
	for i := 0; i < 300; i++ {
		bt = bt.Add(time.Duration(r.ExpFloat64() * 2 * float64(time.Second)))
		name := benign[r.IntN(len(benign))]
		if r.IntN(10) == 0 {
			name = fmt.Sprintf("e%d.dscb.akamaiedge.net", 1000+r.IntN(12))
		}
		s.dnsQuery(bt, "10.0.0.7", "10.0.0.53", name, layers.DNSTypeA, id)
		s.dnsResp(bt.Add(15*time.Millisecond), "10.0.0.7", "10.0.0.53", name, layers.DNSTypeA, id, layers.DNSResponseCodeNoErr,
			[]layers.DNSResourceRecord{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 60, IP: net.IPv4(93, 184, 216, byte(i))}})
		id++
	}
	// DGA: 60 random .com names, all NXDOMAIN.
	dt := s.now
	for i := 0; i < 60; i++ {
		dt = dt.Add(300 * time.Millisecond)
		label := make([]byte, 12+r.IntN(6))
		for j := range label {
			label[j] = byte('a' + r.IntN(26))
		}
		name := string(label) + ".com"
		s.dnsQuery(dt, "10.0.0.9", "10.0.0.53", name, layers.DNSTypeA, id)
		s.dnsResp(dt.Add(10*time.Millisecond), "10.0.0.9", "10.0.0.53", name, layers.DNSTypeA, id, layers.DNSResponseCodeNXDomain, nil)
		id++
	}
	res := s.analyze(Config{})

	tun := findBy(res, CatDNS, "evil-tunnel.com")
	if tun == nil || tun.Score < 0.85 {
		t.Fatalf("tunnel not detected as critical: %+v", tun)
	}
	for _, d := range []string{"google.com", "akamaiedge.net", "office365.com", "bing.com"} {
		if f := findBy(res, CatDNS, d); f != nil && f.Score >= 0.2 {
			t.Errorf("benign %s scored %.2f: %+v", d, f.Score, f.Signals)
		}
	}
	dga := findBy(res, CatDGA, "10.0.0.9")
	if dga == nil || dga.Score < 0.4 {
		t.Errorf("DGA not detected: %+v", dga)
	}
	if f := findBy(res, CatDGA, "10.0.0.7"); f != nil {
		t.Errorf("benign client flagged as DGA: %+v", f)
	}
	// Encoded-volume estimate should be in the right ballpark: 400×30 bytes.
	for _, d := range res.DNS {
		if d.Domain == "evil-tunnel.com" && (d.EncodedBytes < 10000 || d.EncodedBytes > 16000) {
			t.Errorf("encoded estimate %d, want ≈12000", d.EncodedBytes)
		}
	}
	t.Logf("tunnel %.2f %+v", tun.Score, tun.Signals)
}

// ---------------------------------------------------------------- HTTP

func TestHTTPReassemblyChunkedAndBeacon(t *testing.T) {
	s := newSynth(t)
	ts := s.now
	r := mrand.New(mrand.NewPCG(3, 4))
	// Keep-alive connection, 30 check-ins 5s apart. Each request sends
	// headers and body in *separate* segments (what the old tool missed),
	// with a retransmitted segment thrown in; responses are chunked with
	// chunk boundaries straddling segments.
	sess := s.tcp(ts, "10.1.1.10", 51000, "203.0.113.50", 80)
	for i := 0; i < 30; i++ {
		ts = ts.Add(time.Duration((5 + 0.3*(r.Float64()*2-1)) * float64(time.Second)))
		body := randB(600)
		hdr := fmt.Sprintf("POST /api/v1/sync HTTP/1.1\r\nHost: cdn-sync.example\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", len(body))
		sess.Send(ts, true, []byte(hdr), 1400)
		sess.Retransmit = i%7 == 0
		sess.Send(ts.Add(5*time.Millisecond), true, body, 400)
		resp := randB(300)
		chunked := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n", 200)
		full := append([]byte(chunked), resp[:200]...)
		full = append(full, []byte(fmt.Sprintf("\r\n%x\r\n", 100))...)
		full = append(full, resp[200:]...)
		full = append(full, []byte("\r\n0\r\n\r\n")...)
		sess.Send(ts.Add(40*time.Millisecond), false, full, 137)
	}
	sess.Close(ts.Add(time.Second))
	res := s.analyze(Config{})

	if res.Counters.HTTPMessages != 60 {
		t.Fatalf("parsed %d HTTP messages, want 60", res.Counters.HTTPMessages)
	}
	if len(res.HTTP) != 1 {
		t.Fatalf("http channels %d", len(res.HTTP))
	}
	h := res.HTTP[0]
	if h.UploadB != 30*600 || h.DownloadB != 30*300 {
		t.Errorf("body bytes up=%d down=%d (retransmissions or chunk framing leaked in?)", h.UploadB, h.DownloadB)
	}
	if h.RandomUp != 30 || h.RandomDown != 30 {
		t.Errorf("random bodies %d/%d, want 30/30", h.RandomUp, h.RandomDown)
	}
	if h.LegacyHits != 0 {
		t.Errorf("600-byte random bodies can't reach Shannon 7.8 reliably; legacy hits %d", h.LegacyHits)
	}
	c2 := findBy(res, CatC2, "203.0.113.50")
	if c2 == nil || c2.Score < 0.65 {
		t.Fatalf("beaconing random-body channel not flagged high: %+v", c2)
	}
	var sawBeacon bool
	for _, sg := range c2.Signals {
		sawBeacon = sawBeacon || sg.Name == "beacon_timing" && sg.Score > 0.5
	}
	if !sawBeacon {
		t.Errorf("no beacon signal: %+v", c2.Signals)
	}
}

// ---------------------------------------------------------------- SMB2

func smb2Hdr(cmd uint16, resp bool, mid uint64, tree uint32, status uint32) []byte {
	return sy.SMB2Hdr(cmd, resp, mid, tree, status)
}

func nb(msg []byte) []byte { return sy.NB(msg) }

func u16le(s string) []byte { return sy.U16LE(s) }

func havocPacket(n int) []byte {
	p := make([]byte, 12+n)
	binary.BigEndian.PutUint32(p, uint32(8+n))
	binary.BigEndian.PutUint32(p[4:], 0xDEADBEEF)
	binary.BigEndian.PutUint32(p[8:], 0x2db5bcb0)
	copy(p[12:], randB(n))
	return p
}

func TestSMB2PipeTracking(t *testing.T) {
	e := New(Config{})
	c := &tcpConn{ch: &channel{}}
	st := newSMBState(e, c)
	cli, srv := &smbHalf{st: st, client: true}, &smbHalf{st: st}
	ts := time.Now()

	// TREE_CONNECT \\host\IPC$
	path := u16le(`\\192.168.1.11\IPC$`)
	tc := make([]byte, 8)
	binary.LittleEndian.PutUint16(tc[0:], 9)
	binary.LittleEndian.PutUint16(tc[4:], 64+8)
	binary.LittleEndian.PutUint16(tc[6:], uint16(len(path)))
	cli.feed(nb(append(append(smb2Hdr(smbCmdTreeConnect, false, 1, 0, 0), tc...), path...)), ts, 1)
	srv.feed(nb(append(smb2Hdr(smbCmdTreeConnect, true, 1, 7, 0), make([]byte, 16)...)), ts, 2)

	// CREATE "gainz"
	name := u16le("gainz")
	cr := make([]byte, 56)
	binary.LittleEndian.PutUint16(cr[0:], 57)
	binary.LittleEndian.PutUint16(cr[44:], 64+56)
	binary.LittleEndian.PutUint16(cr[46:], uint16(len(name)))
	cli.feed(nb(append(append(smb2Hdr(smbCmdCreate, false, 2, 7, 0), cr...), name...)), ts, 3)
	crr := make([]byte, 88)
	binary.LittleEndian.PutUint16(crr[0:], 89)
	binary.LittleEndian.PutUint32(crr[4:], 1)
	copy(crr[64:80], bytes.Repeat([]byte{0xab}, 16))
	srv.feed(nb(append(smb2Hdr(smbCmdCreate, true, 2, 7, 0), crr...)), ts, 4)

	// WRITE 3 Havoc packets in one write, split across two TCP feeds.
	data := append(append(havocPacket(100), havocPacket(50)...), havocPacket(10)...)
	wr := make([]byte, 48)
	binary.LittleEndian.PutUint16(wr[0:], 49)
	binary.LittleEndian.PutUint16(wr[2:], 64+48)
	binary.LittleEndian.PutUint32(wr[4:], uint32(len(data)))
	copy(wr[16:32], bytes.Repeat([]byte{0xab}, 16))
	msg := nb(append(append(smb2Hdr(smbCmdWrite, false, 3, 7, 0), wr...), data...))
	cli.feed(msg[:50], ts, 5)
	cli.feed(msg[50:], ts, 6)

	// READ request + response carrying a Havoc packet.
	rd := make([]byte, 48)
	binary.LittleEndian.PutUint16(rd[0:], 49)
	copy(rd[16:32], bytes.Repeat([]byte{0xab}, 16))
	cli.feed(nb(append(smb2Hdr(smbCmdRead, false, 4, 7, 0), rd...)), ts, 7)
	out := havocPacket(200)
	rr := make([]byte, 16)
	binary.LittleEndian.PutUint16(rr[0:], 17)
	rr[2] = 64 + 16
	binary.LittleEndian.PutUint32(rr[4:], uint32(len(out)))
	srv.feed(nb(append(append(smb2Hdr(smbCmdRead, true, 4, 7, 0), rr...), out...)), ts, 8)

	if len(st.order) != 1 {
		t.Fatalf("files: %d", len(st.order))
	}
	f := st.order[0]
	if !f.isPipe() || f.pipeName() != "gainz" || f.Share != `\\192.168.1.11\IPC$` {
		t.Errorf("pipe=%v name=%q share=%q", f.isPipe(), f.pipeName(), f.Share)
	}
	if f.WriteBytes != int64(len(data)) || f.ReadBytes != int64(len(out)) {
		t.Errorf("bytes w=%d r=%d", f.WriteBytes, f.ReadBytes)
	}
	if f.magicHits != 4 {
		t.Errorf("magic hits %d, want 4", f.magicHits)
	}
	if known, _ := classifyPipe("gainz"); known {
		t.Error("gainz should be unknown")
	}
	if known, _ := classifyPipe("srvsvc"); !known {
		t.Error("srvsvc should be known")
	}
	if _, p := classifyPipe("msagent_4f"); p == "" {
		t.Error("msagent_ should match C2 prefix")
	}
}

func TestNTLMParse(t *testing.T) {
	// Minimal NTLMSSP AUTHENTICATE with domain/user/workstation.
	dom, usr, ws := u16le("SEVENKINGDOMS"), u16le("vagrant"), u16le("CST-WKS01")
	m := make([]byte, 64)
	copy(m, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(m[8:], 3)
	off := 64
	put := func(at int, b []byte) {
		binary.LittleEndian.PutUint16(m[at:], uint16(len(b)))
		binary.LittleEndian.PutUint16(m[at+2:], uint16(len(b)))
		binary.LittleEndian.PutUint32(m[at+4:], uint32(off))
		off += len(b)
	}
	put(28, dom)
	put(36, usr)
	put(44, ws)
	m = append(append(append(m, dom...), usr...), ws...)
	d, u, w, ok := parseNTLMAuth(append([]byte("junk-spnego-wrapper"), m...))
	if !ok || d != "SEVENKINGDOMS" || u != "vagrant" || w != "CST-WKS01" {
		t.Errorf("got %q %q %q %v", d, u, w, ok)
	}
}

// ---------------------------------------------------------------- helpers

func TestBaseDomain(t *testing.T) {
	for in, want := range map[string]string{
		"a.b.example.com": "example.com", "x.y.bbc.co.uk": "bbc.co.uk", "example.com.": "example.com", "localhost": "localhost",
	} {
		if got := baseDomain(in); got != want {
			t.Errorf("%s → %s want %s", in, got, want)
		}
	}
}

func TestSNI(t *testing.T) {
	// ClientHello with only an SNI extension for "evil.example".
	host := "evil.example"
	sni := []byte{0, 0}
	sni = binary.BigEndian.AppendUint16(sni, uint16(len(host)+5))
	sni = binary.BigEndian.AppendUint16(sni, uint16(len(host)+3))
	sni = append(sni, 0)
	sni = binary.BigEndian.AppendUint16(sni, uint16(len(host)))
	sni = append(sni, host...)
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)                // session id
	body = append(body, 0, 2, 0x13, 0x01) // ciphers
	body = append(body, 1, 0)             // compression
	body = binary.BigEndian.AppendUint16(body, uint16(len(sni)))
	body = append(body, sni...)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	if got := parseSNI(rec); got != host {
		t.Errorf("sni %q", got)
	}
}
