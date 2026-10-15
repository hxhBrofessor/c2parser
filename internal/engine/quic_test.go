package engine

import (
	"net/netip"
	"regexp"

	"bytes"
	"c2parser/internal/pcapio"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	sy "c2parser/internal/synth"
)

func unhex(t testing.TB, s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// v10a 2.3 Gate 1: Initial secrets and keys, byte for byte (RFC 9001 A.1,
// RFC 9369 A.1; DCID 8394c8f03e515708).
func TestQUICInitialKeyVectors(t *testing.T) {
	dcid := unhex(t, "8394c8f03e515708")
	cases := []struct {
		version             uint32
		client              bool
		secret, key, iv, hp string
	}{
		{quicV1, true, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
			"1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c", "9f50449e04a0e810283a1e9933adedd2"},
		{quicV1, false, "", "cf3a5331653c364c88f0f379b6067e37", "0ac1493ca1905853b0bba03e", "c206b8d9b9f0f37644430b490eeaa314"},
		{quicV2, true, "14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b",
			"8b1a0bc121284290a29e0971b5cd045d", "91f73e2351d8fa91660e909f", "45b95e15235d6f45a6b19cbcb0294ba9"},
		{quicV2, false, "", "82db637861d55e1d011f19ea71d5d2a7", "dd13c276499c0249d3310652", "edf6d05c83121201b436e16877593c3a"},
	}
	for _, c := range cases {
		k, err := quicInitialKeys(c.version, dcid, c.client)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string][]byte{"key": k.key, "iv": k.iv, "hp": k.hp}
		want := map[string]string{"key": c.key, "iv": c.iv, "hp": c.hp}
		if c.secret != "" {
			got["secret"], want["secret"] = k.secret, c.secret
		}
		for n, w := range want {
			if hex.EncodeToString(got[n]) != w {
				t.Errorf("v=%#x client=%v %s = %x, want %s", c.version, c.client, n, got[n], w)
			}
		}
	}
	// header protection: RFC 9001 A.2 sample → mask
	k, _ := quicInitialKeys(quicV1, dcid, true)
	if m := hex.EncodeToString(k.hpMask(unhex(t, "d1b1c98dd7689fb8ec11d242b123dc9b"))); m != "437b9aec36" {
		t.Errorf("A.2 mask %s, want 437b9aec36", m)
	}
}

// RFC 9001 A.2 client Initial: the CRYPTO frame carrying the example
// ClientHello (SNI example.com), PN 2, padded to 1162 bytes.
const rfcA2Crypto = "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff"

// Protecting the RFC plaintext reproduces the RFC's protected header and
// sample (so the fixture and the protection are both right), and the
// engine's unprotect recovers the payload and ClientHello.
func TestQUICRFCA2(t *testing.T) {
	dcid := unhex(t, "8394c8f03e515708")
	pkt := sy.QUICInitial(sy.QUICv1, dcid, nil, 2, unhex(t, rfcA2Crypto), 1162)
	if h := hex.EncodeToString(pkt[:22]); h != "c000000001088394c8f03e5157080000449e7b9aec34" {
		t.Errorf("protected header %s", h)
	}
	if s := hex.EncodeToString(pkt[22:38]); s != "d1b1c98dd7689fb8ec11d242b123dc9b" {
		t.Errorf("sample %s", s)
	}
	p, ok := parseQUICLong(pkt)
	if !ok || !p.initial || p.pnOffset != 18 || p.end != len(pkt) {
		t.Fatalf("parse: %+v %v", p, ok)
	}
	k, _ := quicInitialKeys(quicV1, p.dcid, true)
	pl, err := k.unprotect(pkt, p)
	if err != nil || !bytes.HasPrefix(pl, unhex(t, "060040f1")) {
		t.Fatalf("unprotect: %v %x", err, pl[:8])
	}
	fr, ok := cryptoFrames(pl)
	var cs cryptoStream
	for o, b := range fr {
		cs.add(o, b)
	}
	body, done := cs.clientHello()
	h, okh := parseClientHello(body)
	if !ok || !done || !okh || h.sni != "example.com" || !strings.HasPrefix(h.ja4(true), "q13d") {
		t.Fatalf("ClientHello: ok=%v done=%v sni=%q ja4=%s", ok, done, h.sni, h.ja4(true))
	}
	// too short to sample → rejected, not a crash
	if _, err := k.unprotect(pkt[:30], parseLongOr(t, pkt[:30])); err == nil {
		t.Error("too-short packet accepted")
	}
}

func parseLongOr(t *testing.T, b []byte) quicLong {
	p, ok := parseQUICLong(b)
	if !ok {
		p = quicLong{pnOffset: 18, end: len(b)}
	}
	return p
}

// End to end through the engine: v1 and v2 Initials, the ClientHello split
// over two packets in reverse CRYPTO order, a second connection reusing
// the first's keys after a DCID change. SNI and JA4 q land on the channel.
func TestQUICEngine(t *testing.T) {
	for _, v := range []uint32{sy.QUICv1, sy.QUICv2} {
		s := newSynth(t)
		s.b.QUICSession(s.now, "10.8.0.5", 55000, "198.51.100.120", 443, v, []byte{9, 8, 7, 6, 5, 4, 3, 2}, "h3.example.net", 2, 3)
		res := s.analyze(Config{})
		if res.Counters.QUICClientHellos != 1 {
			t.Fatalf("v=%#x: %d ClientHellos (errors %d)", v, res.Counters.QUICClientHellos, res.Counters.QUICInitialErrors)
		}
		var got *ChannelSummary
		for i := range res.TopTalkers {
			if res.TopTalkers[i].Server == "198.51.100.120" {
				got = &res.TopTalkers[i]
			}
		}
		if got == nil || got.SNI != "h3.example.net" || !strings.HasPrefix(got.JA4, "q13d") || !got.QUIC {
			t.Fatalf("v=%#x channel: %+v", v, got)
		}
	}
}

// QUIC SNI feeds the K1 name key: a QUIC beacon over 3 server IPs with one
// SNI rolls up into one v2 finding.
func TestQUICK1Rollup(t *testing.T) {
	s := newSynth(t)
	ts := s.now
	ips := []string{"203.0.113.31", "203.0.113.32", "203.0.113.33"}
	for i := 0; i < 60; i++ {
		ts = ts.Add(time.Duration(60*(1-0.1*float64(i%5)/5)) * time.Second)
		s.b.QUICSession(ts, "10.8.0.6", uint16(56000+i), ips[i%3], 443, sy.QUICv1, []byte{byte(i), 1, 2, 3, 4, 5, 6, 7}, "edge-sync.example", 1, 2)
	}
	res := s.analyze(Config{TimingV2: true})
	if res.Counters.QUICClientHellos != 60 {
		t.Fatalf("%d ClientHellos", res.Counters.QUICClientHellos)
	}
	f := findBy(res, CatC2, "edge-sync.example")
	if f == nil || !strings.Contains(f.Title, "3 server IPs") {
		t.Fatalf("no K1 roll-up for the QUIC beacon: %+v", res.Findings)
	}
}

func FuzzQUICInitial(f *testing.F) {
	f.Add(sy.QUICInitial(sy.QUICv1, []byte{1, 2, 3, 4, 5, 6, 7, 8}, nil, 0, sy.CryptoFrame(0, sy.ClientHelloMsg("a.example", nil)), 1162))
	f.Add([]byte{0xc3, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0x40, 0x20})
	f.Fuzz(func(t *testing.T, d []byte) {
		e := New(Config{})
		u := &udpFlow{ch: &channel{}}
		e.onQUICClient(u, d)
		if p, ok := parseQUICLong(d); ok && p.end <= len(d) {
			k, _ := quicInitialKeys(quicV1, p.dcid, true)
			if k != nil {
				k.unprotect(d, p)
			}
		}
	})
}

func FuzzQUICCrypto(f *testing.F) {
	f.Add(unhex(f, rfcA2Crypto), uint8(3))
	f.Fuzz(func(t *testing.T, pl []byte, n uint8) {
		fr, _ := cryptoFrames(pl)
		var cs cryptoStream
		for o, b := range fr {
			cs.add(o, b)
			cs.add(o+uint64(n), b)
		}
		if body, ok := cs.clientHello(); ok {
			parseClientHello(body)
		}
	})
}

// v10a 2.3 Gate 2 (lab): on part2's QUIC flows (Edge, v1), ≥ 95 % of the
// flows with a client Initial in the capture yield a complete ClientHello;
// every SNI is a valid hostname; where a server IP also has TCP TLS, the
// QUIC and TCP SNI sets overlap. JA4 starts with "q" (from the transport).
func TestCaptureQUICPart2(t *testing.T) {
	path := capture(t, "part2")
	r, err := pcapio.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	e := New(Config{})
	if err := e.Ingest(r); err != nil {
		t.Fatal(err)
	}
	r.Close()
	res := e.Finish()
	c := res.Counters
	t.Logf("QUIC: %d flows with a client Initial, %d ClientHellos, %d Initial decrypt errors", c.QUICInitialFlows, c.QUICClientHellos, c.QUICInitialErrors)
	if c.QUICInitialFlows == 0 || float64(c.QUICClientHellos) < 0.95*float64(c.QUICInitialFlows) {
		t.Errorf("ClientHello recovery %d/%d < 95 %%", c.QUICClientHellos, c.QUICInitialFlows)
	}
	host := regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	quicSNI, tcpSNI := map[netip.Addr]map[string]bool{}, map[netip.Addr]map[string]bool{}
	for _, ch := range e.chOrder {
		if ch.tls == nil {
			continue
		}
		m := tcpSNI
		if ch.quic {
			m = quicSNI
			for j4 := range ch.tls.ja4.Map() {
				if !strings.HasPrefix(j4, "q") {
					t.Errorf("QUIC JA4 %s does not start with q", j4)
				}
			}
		}
		for sni := range ch.tls.sni.Map() {
			if ch.quic && !host.MatchString(sni) {
				t.Errorf("invalid QUIC SNI %q", sni)
			}
			if m[ch.key.server] == nil {
				m[ch.key.server] = map[string]bool{}
			}
			m[ch.key.server][sni] = true
		}
	}
	both, overlap := 0, 0
	for ip, qs := range quicSNI {
		ts, ok := tcpSNI[ip]
		if !ok {
			continue
		}
		both++
		for s := range qs {
			if ts[s] {
				overlap++
				break
			}
		}
	}
	t.Logf("%d server IPs with both QUIC and TCP TLS; %d share an SNI", both, overlap)
	if both > 0 && overlap == 0 {
		t.Error("QUIC and TCP SNI sets never overlap on shared server IPs")
	}
}
