package engine

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// FIX-D2b (v11.1): a TCP 4-tuple reused for a later connection (engine.go
// observeTCP finishes the old connection and starts a new one) gave both
// connections the same smb_pipe timing key, because the key held only the
// two AddrPorts and the pipe name. The key now also carries the
// connection's first frame number, which is unique per connection.

func TestSMBPipeTimingKeysTupleReuse(t *testing.T) {
	s := newSynth(t)
	// Same client port twice: the second connection starts after the first
	// has closed, so observeTCP treats the SYN as a new connection.
	smbPipeConn(s, "10.7.0.5", 50001, "10.7.0.11", "reuse_pipe", s.now, randB(64))
	smbPipeConn(s, "10.7.0.5", 50001, "10.7.0.11", "reuse_pipe", s.now.Add(5*time.Minute), randB(64))
	_, results := analyzeRuns(t, s, Config{TimingV2: true}, 10)
	var first []string
	for i, res := range results {
		ss := pipeSeries(res)
		if len(ss) != 2 {
			t.Fatalf("run %d: %d smb_pipe series, want 2 (one per connection)", i, len(ss))
		}
		if distinctKeys(ss) != 2 {
			t.Fatalf("run %d: keys %q and %q collide on 4-tuple reuse", i, ss[0].Key, ss[1].Key)
		}
		for _, x := range ss {
			if !strings.Contains(x.Key, "10.7.0.5:50001|10.7.0.11:445|reuse_pipe|") {
				t.Fatalf("run %d: unexpected key format %q", i, x.Key)
			}
		}
		pipes := 0
		for _, f := range res.Findings {
			if f.Category == CatPipe {
				pipes++
			}
		}
		if pipes != 1 {
			t.Fatalf("run %d: %d pipe findings, want 1 (finding key stays per address pair)", i, pipes)
		}
		keys := []string{ss[0].Key, ss[1].Key}
		if i == 0 {
			first = keys
		} else if keys[0] != first[0] || keys[1] != first[1] {
			t.Fatalf("run %d: keys %v differ from run 0 %v", i, keys, first)
		}
	}
}

// IPv6 endpoints: the key uses the bracketed AddrPort form. Built through the
// engine API because the packet builder is IPv4-only.
func TestSMBPipeTimingKeyIPv6(t *testing.T) {
	ts := time.Date(2024, 3, 25, 12, 0, 0, 0, time.UTC)
	e := New(Config{TimingV2: true})
	e.first, e.last = ts, ts.Add(time.Minute)
	c := &tcpConn{ch: &channel{}, start: ts, last: ts, firstFrame: 7,
		client: netip.MustParseAddrPort("[fd00::5]:50001"), server: netip.MustParseAddrPort("[fd00::11]:445")}
	st := newSMBState(e, c)
	cli, srv := &smbHalf{st: st, client: true}, &smbHalf{st: st}
	path := u16le(`\\fd00--11.ipv6-literal.net\IPC$`)
	tc := make([]byte, 8)
	binary.LittleEndian.PutUint16(tc[0:], 9)
	binary.LittleEndian.PutUint16(tc[4:], 64+8)
	binary.LittleEndian.PutUint16(tc[6:], uint16(len(path)))
	cli.feed(nb(append(append(smb2Hdr(smbCmdTreeConnect, false, 1, 0, 0), tc...), path...)), ts, 1)
	srv.feed(nb(append(smb2Hdr(smbCmdTreeConnect, true, 1, 7, 0), make([]byte, 16)...)), ts, 2)
	name := u16le("v6_pipe")
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
	res := e.Finish()
	ss := pipeSeries(res)
	if len(ss) != 1 {
		t.Fatalf("%d smb_pipe series, want 1", len(ss))
	}
	if want := "pipe|[fd00::5]:50001|[fd00::11]:445|v6_pipe|7"; ss[0].Key != want {
		t.Fatalf("key %q, want %q", ss[0].Key, want)
	}
}
