package engine

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func revSMB(e *Engine) (*smbState, *smbHalf, *smbHalf) {
	c := &tcpConn{ch: &channel{}}
	st := newSMBState(e, c)
	return st, &smbHalf{st: st, client: true}, &smbHalf{st: st}
}

// A: async (STATUS_PENDING) READ loses its FileId.
func TestReviewSMBAsyncRead(t *testing.T) {
	e := New(Config{})
	st, cli, srv := revSMB(e)
	ts := time.Now()
	fid := bytes.Repeat([]byte{0xcd}, 16)
	rd := make([]byte, 48)
	binary.LittleEndian.PutUint16(rd[0:], 49)
	copy(rd[16:32], fid)
	cli.feed(nb(append(smb2Hdr(smbCmdRead, false, 9, 7, 0), rd...)), ts, 1)
	// interim async response: STATUS_PENDING, flags = resp|async, 9-byte error body
	h := smb2Hdr(smbCmdRead, true, 9, 0, 0x103)
	binary.LittleEndian.PutUint32(h[16:], 3)
	srv.feed(nb(append(h, make([]byte, 9)...)), ts, 2)
	// final async response with data
	out := havocPacket(100)
	h2 := smb2Hdr(smbCmdRead, true, 9, 0, 0)
	binary.LittleEndian.PutUint32(h2[16:], 3)
	rr := make([]byte, 16)
	binary.LittleEndian.PutUint16(rr[0:], 17)
	rr[2] = 64 + 16
	binary.LittleEndian.PutUint32(rr[4:], uint32(len(out)))
	srv.feed(nb(append(append(h2, rr...), out...)), ts, 3)
	for _, f := range st.order {
		t.Logf("file fid=%x read=%d", f.fid[:4], f.ReadBytes)
	}
	if len(st.order) != 1 || !bytes.Equal(st.order[0].fid[:], fid) {
		t.Errorf("async READ data attributed to wrong FileId")
	}
}

// F: failed CREATE / unanswered requests leak pending maps.
func TestReviewSMBPendLeak(t *testing.T) {
	e := New(Config{})
	st, cli, srv := revSMB(e)
	ts := time.Now()
	for i := 0; i < 1000; i++ {
		name := u16le(fmt.Sprintf("probe%d.txt", i))
		cr := make([]byte, 56)
		binary.LittleEndian.PutUint16(cr[0:], 57)
		binary.LittleEndian.PutUint16(cr[44:], 64+56)
		binary.LittleEndian.PutUint16(cr[46:], uint16(len(name)))
		cli.feed(nb(append(append(smb2Hdr(smbCmdCreate, false, uint64(i), 7, 0), cr...), name...)), ts, 1)
		srv.feed(nb(append(smb2Hdr(smbCmdCreate, true, uint64(i), 7, 0xC0000034), make([]byte, 9)...)), ts, 2)
	}
	t.Logf("pendCreate after 1000 failed creates: %d", len(st.pendCreate))
	if len(st.pendCreate) != 0 {
		t.Errorf("pendCreate leaks %d entries", len(st.pendCreate))
	}
}

// B: CONNECT 200 tunnel bytes parsed as response body.
func TestReviewHTTPConnect(t *testing.T) {
	e := New(Config{})
	c := &tcpConn{client: netip.MustParseAddrPort("10.0.0.1:5000"), server: netip.MustParseAddrPort("10.0.0.2:3128"), ch: &channel{}}
	cli, srv := newHTTPHalf(e, c, true), newHTTPHalf(e, c, false)
	ts := time.Now()
	cli.feed([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"), ts, 1)
	srv.feed([]byte("HTTP/1.1 200 Connection established\r\n\r\n"), ts, 2)
	cli.feed(randB(4096), ts, 3)
	srv.feed(randB(8192), ts, 4)
	srv.close(ts)
	cli.close(ts)
	for _, h := range e.httpOrder {
		t.Logf("resp=%d down=%d randomDn=%d", h.responses, h.download, h.randomDn)
		if h.download > 0 || h.randomDn > 0 {
			t.Errorf("CONNECT tunnel bytes counted as HTTP response body (%d bytes, %d random)", h.download, h.randomDn)
		}
	}
}

// D: LF-only headers followed by body containing CRLFCRLF.
func TestReviewHTTPLFHeaders(t *testing.T) {
	e := New(Config{})
	c := &tcpConn{client: netip.MustParseAddrPort("10.0.0.1:5000"), server: netip.MustParseAddrPort("10.0.0.2:80"), ch: &channel{}}
	cli := newHTTPHalf(e, c, true)
	var got []int64
	cli.feed([]byte("POST /x HTTP/1.1\nHost: a\nContent-Length: 10\n\nab\r\n\r\ncdefGET /y HTTP/1.1\nHost: a\n\n"), time.Now(), 1)
	for _, h := range e.httpOrder {
		got = append(got, h.upload, int64(h.requests))
	}
	t.Logf("upload,requests=%v", got)
	if len(got) == 0 || got[0] != 10 || got[1] != 2 {
		t.Errorf("LF-only header terminator ignored when body contains CRLFCRLF: %v", got)
	}
}

// C: idle >2min SMB connection is flushed+closed by FlushCloseOlderThan; the
// next packets create a fresh tcpStream + smbState that has lost tree/create state.
func TestReviewIdleFlushSplitsSMB(t *testing.T) {
	s := newSynth(t)
	ts := s.now
	sess := s.tcp(ts, "10.0.0.5", 50123, "10.0.0.6", 445)
	path := u16le(`\\10.0.0.6\IPC$`)
	tc := make([]byte, 8)
	binary.LittleEndian.PutUint16(tc[0:], 9)
	binary.LittleEndian.PutUint16(tc[4:], 64+8)
	binary.LittleEndian.PutUint16(tc[6:], uint16(len(path)))
	sess.Send(ts.Add(10*time.Millisecond), true, nb(append(append(smb2Hdr(smbCmdTreeConnect, false, 1, 0, 0), tc...), path...)), 1400)
	sess.Send(ts.Add(11*time.Millisecond), false, nb(append(smb2Hdr(smbCmdTreeConnect, true, 1, 7, 0), make([]byte, 16)...)), 1400)
	name := u16le("evilpipe")
	cr := make([]byte, 56)
	binary.LittleEndian.PutUint16(cr[0:], 57)
	binary.LittleEndian.PutUint16(cr[44:], 64+56)
	binary.LittleEndian.PutUint16(cr[46:], uint16(len(name)))
	sess.Send(ts.Add(12*time.Millisecond), true, nb(append(append(smb2Hdr(smbCmdCreate, false, 2, 7, 0), cr...), name...)), 1400)
	crr := make([]byte, 88)
	binary.LittleEndian.PutUint16(crr[0:], 89)
	copy(crr[64:80], bytes.Repeat([]byte{0xab}, 16))
	sess.Send(ts.Add(13*time.Millisecond), false, nb(append(smb2Hdr(smbCmdCreate, true, 2, 7, 0), crr...)), 1400)
	// 3 minutes of unrelated UDP so the periodic flush runs with the SMB conn idle
	ft := ts
	for i := 0; i < 21000; i++ {
		ft = ft.Add(10 * time.Millisecond)
		s.udp(ft, "10.0.0.9", 40000, "10.0.0.10", 9999, gopacket.Payload([]byte("x")))
	}
	ts = ft.Add(time.Second)
	data := havocPacket(100)
	wr := make([]byte, 48)
	binary.LittleEndian.PutUint16(wr[0:], 49)
	binary.LittleEndian.PutUint16(wr[2:], 64+48)
	binary.LittleEndian.PutUint32(wr[4:], uint32(len(data)))
	copy(wr[16:32], bytes.Repeat([]byte{0xab}, 16))
	sess.Send(ts, true, nb(append(append(smb2Hdr(smbCmdWrite, false, 3, 7, 0), wr...), data...)), 1400)
	res := s.analyze(Config{})
	for _, p := range res.Pipes {
		t.Logf("pipe %+v", p)
	}
	ok := false
	for _, p := range res.Pipes {
		if p.Name == "evilpipe" && p.WriteBytes > 0 {
			ok = true
		}
	}
	if !ok {
		t.Errorf("write after idle flush not attributed to the named pipe")
	}
}

// ---- fuzz targets
func FuzzReviewSMB(f *testing.F) {
	f.Add(nb(append(smb2Hdr(smbCmdRead, true, 1, 0, 0), make([]byte, 20)...)), 3)
	f.Fuzz(func(t *testing.T, b []byte, split int) {
		e := New(Config{})
		_, cli, srv := revSMB(e)
		if split < 0 {
			split = -split
		}
		if len(b) > 0 {
			split %= len(b) + 1
		} else {
			split = 0
		}
		cli.feed(b[:split], time.Now(), 1)
		cli.feed(b[split:], time.Now(), 1)
		srv.feed(b, time.Now(), 1)
		for i := 0; i+4 <= len(b); i += 4 {
			e.smbStates[0].handle(b[i:], time.Now(), 1)
			if i > 256 {
				break
			}
		}
		parseNTLMAuth(b)
	})
}

func FuzzReviewHTTP(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"), 7)
	f.Fuzz(func(t *testing.T, a, b []byte, split int) {
		e := New(Config{})
		c := &tcpConn{client: netip.MustParseAddrPort("10.0.0.1:5000"), server: netip.MustParseAddrPort("1.2.3.4:80"), ch: &channel{}}
		cli, srv := newHTTPHalf(e, c, true), newHTTPHalf(e, c, false)
		if split < 0 {
			split = -split
		}
		sa := split % (len(a) + 1)
		sb := split % (len(b) + 1)
		cli.feed(a[:sa], time.Now(), 1)
		srv.feed(b[:sb], time.Now(), 1)
		cli.gap()
		cli.feed(a[sa:], time.Now(), 1)
		srv.feed(b[sb:], time.Now(), 1)
		cli.close(time.Now())
		srv.close(time.Now())
		e.score()
	})
}

func FuzzReviewDNSAndSNI(f *testing.F) {
	f.Add([]byte{0x16, 3, 1, 0, 5, 1, 0, 0, 1, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		e := New(Config{})
		e.onDNSPayload(b, netip.MustParseAddrPort("10.0.0.1:5000"), netip.MustParseAddrPort("10.0.0.2:53"), time.Now(), 1)
		e.onDNSPayload(b, netip.MustParseAddrPort("10.0.0.2:53"), netip.MustParseAddrPort("10.0.0.1:5000"), time.Now(), 1)
		h := &dnsTCPHalf{e: e, c: &tcpConn{}, client: true}
		h.feed(b, time.Now(), 1)
		parseSNI(b)
		e.score()
	})
}

// whole pipeline on arbitrary file bytes (pcap / pcapng)
func FuzzReviewFile(f *testing.F) {
	f.Add([]byte("\x0a\x0d\x0d\x0a\x1c\x00\x00\x00\x4d\x3c\x2b\x1a\x01\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x1c\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		p := filepath.Join(t.TempDir(), "f.pcap")
		os.WriteFile(p, b, 0o600)
		AnalyzeFile(p, Config{})
	})
}

var _ = layers.LinkTypeEthernet

func FuzzTLSHello(f *testing.F) {
	f.Add(clientHello("a.example", []string{"h2", "dot"}))
	f.Fuzz(func(t *testing.T, b []byte) {
		hs, _ := tlsHandshakeBytes(b)
		if len(hs) >= 4 {
			if h, ok := parseClientHello(hs[4:]); ok {
				h.ja3()
				h.ja4(false)
			}
			parseServerHello(hs[4:])
			parseCertificateMsg(hs[4:])
		}
		e := New(Config{})
		c := &tcpConn{ch: &channel{}}
		(&tlsHalf{e: e, c: c, client: true}).feed(b, time.Now(), 1)
		(&tlsHalf{e: e, c: c}).feed(b, time.Now(), 1)
	})
}
