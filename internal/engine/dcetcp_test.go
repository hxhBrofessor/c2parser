package engine

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// ---------------------------------------------------------------- builders

func uuidBytes(u string) []byte {
	h := strings.ReplaceAll(u, "-", "")
	raw := make([]byte, 16)
	for i := 0; i < 16; i++ {
		var v byte
		for _, c := range h[2*i : 2*i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			default:
				v |= byte(c-'a') + 10
			}
		}
		raw[i] = v
	}
	out := make([]byte, 16)
	// time_low, time_mid, time_hi little-endian; the rest as is
	out[0], out[1], out[2], out[3] = raw[3], raw[2], raw[1], raw[0]
	out[4], out[5] = raw[5], raw[4]
	out[6], out[7] = raw[7], raw[6]
	copy(out[8:], raw[8:])
	return out
}

// dcePDU frames a PDU: header (16) + body (+ sec_trailer and auth value
// when level > 0).
func dcePDU(typ byte, flags byte, callID uint32, body []byte, level uint8) []byte {
	var auth []byte
	if level > 0 {
		pad := (4 - (16+len(body))%4) % 4
		body = append(body, make([]byte, pad)...)
		auth = []byte{9, level, byte(pad), 0, 0, 0, 0, 0}
		auth = append(auth, make([]byte, 16)...) // 16-byte auth value
	}
	h := []byte{5, 0, typ, flags, 0x10, 0, 0, 0, 0, 0, 0, 0}
	total := 16 + len(body) + len(auth)
	binary.LittleEndian.PutUint16(h[8:], uint16(total))
	if level > 0 {
		binary.LittleEndian.PutUint16(h[10:], 16)
	}
	h = binary.LittleEndian.AppendUint32(h, callID)
	return append(append(h, body...), auth...)
}

func tcpBind(callID uint32, ctxs map[uint16]string, level uint8) []byte {
	b := []byte{0xb8, 0x10, 0xb8, 0x10, 0, 0, 0, 0, byte(len(ctxs)), 0, 0, 0}
	for id := uint16(0); id < 16; id++ {
		u, ok := ctxs[id]
		if !ok {
			continue
		}
		e := binary.LittleEndian.AppendUint16(nil, id)
		e = append(e, 1, 0)
		e = append(e, uuidBytes(u)...)
		e = append(e, 1, 0, 0, 0) // version
		e = append(e, uuidBytes("8a885d04-1ceb-11c9-9fe8-08002b104860")...)
		e = append(e, 2, 0, 0, 0)
		b = append(b, e...)
	}
	return dcePDU(11, 0x03, callID, b, level)
}

func dceBindAck(callID uint32, results []uint16) []byte {
	b := []byte{0xb8, 0x10, 0xb8, 0x10, 1, 0, 0, 0}
	sec := []byte("49668\x00")
	b = binary.LittleEndian.AppendUint16(b, uint16(len(sec)))
	b = append(b, sec...)
	for (16+len(b))%4 != 0 {
		b = append(b, 0)
	}
	b = append(b, byte(len(results)), 0, 0, 0)
	for _, r := range results {
		e := binary.LittleEndian.AppendUint16(nil, r)
		e = append(e, 0, 0)
		e = append(e, make([]byte, 20)...)
		b = append(b, e...)
	}
	return dcePDU(12, 0x03, callID, b, 0)
}

func tcpRequest(callID uint32, ctx, opnum uint16, stub []byte, flags byte, level uint8) []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(len(stub)))
	b = binary.LittleEndian.AppendUint16(b, ctx)
	b = binary.LittleEndian.AppendUint16(b, opnum)
	return dcePDU(0, flags, callID, append(b, stub...), level)
}

func dceResponse(callID uint32, stub []byte, flags byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(len(stub)))
	b = append(b, 0, 0, 0, 0)
	return dcePDU(2, flags, callID, append(b, stub...), 0)
}

// tower builds an ncacn_ip_tcp protocol tower for uuid at ip:port.
func tower(uuid string, ip string, port uint16) []byte {
	floor := func(lhs, rhs []byte) []byte {
		b := binary.LittleEndian.AppendUint16(nil, uint16(len(lhs)))
		b = append(b, lhs...)
		b = binary.LittleEndian.AppendUint16(b, uint16(len(rhs)))
		return append(b, rhs...)
	}
	t := binary.LittleEndian.AppendUint16(nil, 5)
	t = append(t, floor(append(append([]byte{0x0d}, uuidBytes(uuid)...), 4, 0), []byte{0, 0})...)
	t = append(t, floor(append([]byte{0x0d}, append(uuidBytes("8a885d04-1ceb-11c9-9fe8-08002b104860"), 2, 0)...), []byte{0, 0})...)
	t = append(t, floor([]byte{0x0b}, []byte{0, 0})...)
	t = append(t, floor([]byte{0x07}, []byte{byte(port >> 8), byte(port)})...)
	a := netip.MustParseAddr(ip).As4()
	t = append(t, floor([]byte{0x09}, a[:])...)
	return t
}

// eptMapResponse is an ept_map response stub carrying the towers.
func eptMapResponse(towers ...[]byte) []byte {
	s := make([]byte, 20) // entry handle
	s = binary.LittleEndian.AppendUint32(s, uint32(len(towers)))
	s = binary.LittleEndian.AppendUint32(s, 4)                   // max
	s = binary.LittleEndian.AppendUint32(s, 0)                   // offset
	s = binary.LittleEndian.AppendUint32(s, uint32(len(towers))) // actual
	for i := range towers {
		s = binary.LittleEndian.AppendUint32(s, uint32(0x20000+i))
	}
	for _, t := range towers {
		s = binary.LittleEndian.AppendUint32(s, uint32(len(t)))
		s = binary.LittleEndian.AppendUint32(s, uint32(len(t)))
		s = append(s, t...)
		for len(s)%4 != 0 {
			s = append(s, 0)
		}
	}
	return binary.LittleEndian.AppendUint32(s, 0) // status
}

// oxidStub wraps a DUALSTRINGARRAY entry "host[port]" in filler bytes, as
// it sits inside a RemoteCreateInstance activation blob.
func oxidStub(binding string) []byte {
	s := make([]byte, 64)
	for i := range s {
		s[i] = byte(0x80 + i%32)
	}
	s = binary.LittleEndian.AppendUint16(s, 3)    // wNumEntries
	s = binary.LittleEndian.AppendUint16(s, 0x30) // wSecurityOffset
	s = binary.LittleEndian.AppendUint16(s, 0x07) // ncacn_ip_tcp
	for _, c := range utf16.Encode([]rune(binding)) {
		s = binary.LittleEndian.AppendUint16(s, c)
	}
	return append(s, 0, 0, 0, 0, 0xaa, 0xbb)
}

// dceSession writes a raw-TCP DCE/RPC exchange: client PDUs and server
// PDUs alternating as given.
type dceStep struct {
	client bool
	pdu    []byte
}

func dceSession(s *synth, ts time.Time, cli string, cport uint16, srv string, sport uint16, steps ...dceStep) time.Time {
	c := s.tcp(ts, cli, cport, srv, sport)
	ts = ts.Add(3 * time.Millisecond)
	for _, st := range steps {
		ts = c.Send(ts.Add(2*time.Millisecond), st.client, st.pdu, 1400)
	}
	c.Close(ts.Add(5 * time.Millisecond))
	return ts.Add(10 * time.Millisecond)
}

func rpcRow(res *Result, client, ep, op, transport string) *RPCCall {
	for i := range res.RPCCalls {
		r := &res.RPCCalls[i]
		if (client == "" || r.Client == client) && r.Endpoint == ep && r.Op == op && r.Transport == transport {
			return r
		}
	}
	return nil
}

// ---------------------------------------------------------------- tests

const (
	uuidWbem = "9556dc99-828c-11cf-a37e-00aa003240c7"
)

// v10a 2.1: DCE/RPC on a dynamic TCP port is found by its PDU header and a
// WMI ExecMethod over it is a lateral finding with transport tcp.
func TestDCERPCTCPWMI(t *testing.T) {
	s := newSynth(t)
	dceSession(s, s.now, "10.7.0.5", 50100, "10.7.0.20", 49711,
		dceStep{true, tcpBind(1, map[uint16]string{0: uuidWbem}, 0)},
		dceStep{false, dceBindAck(1, []uint16{0})},
		dceStep{true, tcpRequest(2, 0, 24, make([]byte, 64), 0x03, 0)},
		dceStep{false, dceResponse(2, make([]byte, 32), 0x03)})
	res := s.analyze(Config{})
	r := rpcRow(res, "10.7.0.5", "IWbemServices", "ExecMethod", "tcp")
	if r == nil || r.Count != 1 || !r.Bound || len(r.Ports) != 1 || r.Ports[0] != 49711 {
		t.Fatalf("rpc_calls: %+v", res.RPCCalls)
	}
	f := findBy(res, CatLateral, "tcp/49711")
	if f == nil || f.Score < 0.6 {
		t.Fatalf("no lateral finding over tcp/49711: %+v", res.Findings)
	}
}

// A rejected presentation context (BIND_ACK result ≠ 0) is not attributed.
func TestDCERPCBindAckRejected(t *testing.T) {
	s := newSynth(t)
	dceSession(s, s.now, "10.7.0.5", 50101, "10.7.0.20", 49712,
		dceStep{true, tcpBind(1, map[uint16]string{0: uuidWbem}, 0)},
		dceStep{false, dceBindAck(1, []uint16{2})}, // provider rejection
		dceStep{true, tcpRequest(2, 0, 24, make([]byte, 64), 0x03, 0)})
	res := s.analyze(Config{})
	if r := rpcRow(res, "", "IWbemServices", "ExecMethod", "tcp"); r != nil {
		t.Errorf("call on a rejected context attributed: %+v", r)
	}
	if r := rpcRow(res, "", "unbound", "opnum_24", "tcp"); r == nil || r.Bound {
		t.Errorf("want unbound:opnum_24, got %+v", res.RPCCalls)
	}
}

// ept_map (TCP/135) teaches the dynamic port's interface; a stream on that
// port whose BIND wasn't captured is labelled from it. Mutation: without
// the learning the stream goes back to unbound.
func TestDCERPCEPMLearning(t *testing.T) {
	run := func() *Result {
		s := newSynth(t)
		ts := dceSession(s, s.now, "10.7.0.5", 50102, "10.7.0.10", 135,
			dceStep{true, tcpBind(1, map[uint16]string{0: uuidEPM}, 0)},
			dceStep{false, dceBindAck(1, []uint16{0})},
			dceStep{true, tcpRequest(2, 0, 3, make([]byte, 80), 0x03, 0)},
			dceStep{false, dceResponse(2, eptMapResponse(tower(uuidDRSUAPI, "10.7.0.10", 49668)), 0x03)})
		// the drsuapi stream: BIND predates the capture (requests only)
		c := s.tcp(ts, "10.7.0.5", 50103, "10.7.0.10", 49668)
		x := ts.Add(5 * time.Millisecond)
		for i := 0; i < 3; i++ {
			x = c.Send(x.Add(time.Millisecond), true, tcpRequest(uint32(10+i), 0, 12, make([]byte, 40), 0x03, 5), 1400)
		}
		c.Close(x.Add(time.Millisecond))
		return s.analyze(Config{})
	}
	res := run()
	r := rpcRow(res, "10.7.0.5", "drsuapi", "DRSCrackNames", "tcp")
	if r == nil || r.Count != 3 || r.Bound || r.Learned != "ept_map" || r.AuthLevel != "integrity" {
		t.Fatalf("learned drsuapi row: %+v (all: %+v)", r, res.RPCCalls)
	}
	if e := rpcRow(res, "10.7.0.5", "epmapper", "ept_map", "tcp"); e == nil || e.Count != 1 {
		t.Errorf("epmapper ept_map row: %+v", res.RPCCalls)
	}
	dceLearning = false
	res = run()
	dceLearning = true
	if r := rpcRow(res, "10.7.0.5", "unbound", "opnum_12", "tcp"); r == nil || r.Count != 3 {
		t.Errorf("mutation: without EPM learning the stream should be unbound: %+v", res.RPCCalls)
	}
}

// A DCOM activation response's OXID binding teaches the object exporter's
// port: later requests there are "dcom-object", not unbound.
func TestDCERPCOXIDLearning(t *testing.T) {
	s := newSynth(t)
	ts := dceSession(s, s.now, "10.7.0.5", 50104, "10.7.0.21", 135,
		dceStep{true, tcpBind(1, map[uint16]string{0: uuidActivator}, 0)},
		dceStep{false, dceBindAck(1, []uint16{0})},
		dceStep{true, tcpRequest(2, 0, 4, make([]byte, 200), 0x03, 0)},
		dceStep{false, dceResponse(2, oxidStub("10.7.0.21[49801]"), 0x03)})
	c := s.tcp(ts, "10.7.0.5", 50105, "10.7.0.21", 49801)
	c.Close(c.Send(ts.Add(5*time.Millisecond), true, tcpRequest(5, 1, 3, make([]byte, 40), 0x03, 0), 1400).Add(time.Millisecond))
	res := s.analyze(Config{})
	if r := rpcRow(res, "10.7.0.5", "dcom-object", "opnum_3", "tcp"); r == nil || r.Learned != "oxid" {
		t.Fatalf("oxid-learned row missing: %+v", res.RPCCalls)
	}
	if r := rpcRow(res, "10.7.0.5", "IRemoteSCMActivator", "RemoteCreateInstance", "tcp"); r == nil {
		t.Errorf("activation row missing: %+v", res.RPCCalls)
	}
	if f := findBy(res, CatLateral, "10.7.0.21"); f == nil || !hasSignal(f, "rpc:IRemoteSCMActivator:RemoteCreateInstance") {
		t.Errorf("DCOM activation not scored: %+v", f)
	}
}

// DC guard: DRSGetNCChanges from a domain controller is replication (info);
// from any other host it is dcsync_from_non_dc (high, never critical
// alone). Mutation: without the guard the DC client is flagged too.
func TestDCERPCDCGuard(t *testing.T) {
	build := func(client string) *Result {
		s := newSynth(t)
		ts := s.now
		if client == "10.7.0.11" { // the client is a DC: it serves LDAP
			c := s.tcp(ts, "10.7.0.50", 50200, client, 389)
			c.Close(c.Send(ts.Add(3*time.Millisecond), true, []byte{0x30, 0x05, 0x02, 0x01, 0x01, 0x42, 0x00}, 1400))
			ts = ts.Add(time.Second)
		}
		dceSession(s, ts, client, 50201, "10.7.0.10", 49668,
			dceStep{true, tcpBind(1, map[uint16]string{0: uuidDRSUAPI}, 0)},
			dceStep{false, dceBindAck(1, []uint16{0})},
			dceStep{true, tcpRequest(2, 0, 3, make([]byte, 100), 0x03, 6)},
			dceStep{true, tcpRequest(3, 0, 3, make([]byte, 100), 0x03, 6)})
		return s.analyze(Config{AllPairs: true})
	}
	dc := build("10.7.0.11")
	if f := findBy(dc, CatLateral, "10.7.0.11"); f != nil {
		t.Errorf("DC↔DC replication flagged: %+v", f)
	}
	info := findBy(dc, CatDCRepl, "10.7.0.11")
	if info == nil || info.Score >= 0.2 || !hasSignal(info, "dc_replication") {
		t.Errorf("want an info DC replication note, got %+v", info)
	}
	non := build("10.7.0.99")
	f := findBy(non, CatLateral, "10.7.0.99")
	if f == nil || !hasSignal(f, "dcsync_from_non_dc") || f.Score < 0.6 || f.Score >= 0.85 {
		t.Errorf("non-DC DRSGetNCChanges: %+v", f)
	}
	dcGuard = false
	mut := build("10.7.0.11")
	dcGuard = true
	if f := findBy(mut, CatLateral, "10.7.0.11"); f == nil || !hasSignal(f, "dcsync_from_non_dc") {
		t.Errorf("mutation: guard removed but the DC client is not flagged: %+v", mut.Findings)
	}
	// -dc declares a DC explicitly
	s := newSynth(t)
	dceSession(s, s.now, "10.7.0.12", 50202, "10.7.0.10", 49668,
		dceStep{true, tcpBind(1, map[uint16]string{0: uuidDRSUAPI}, 0)},
		dceStep{true, tcpRequest(2, 0, 3, make([]byte, 100), 0x03, 6)})
	if f := findBy(s.analyze(Config{DCs: []netip.Addr{netip.MustParseAddr("10.7.0.12")}}), CatLateral, "10.7.0.12"); f != nil {
		t.Errorf("-dc host flagged: %+v", f)
	}
}

// Multi-fragment PDUs: a request split in fragments counts once; an
// ept_map response split in two fragments is reassembled; sealed responses
// are not read.
func TestDCERPCFragments(t *testing.T) {
	s := newSynth(t)
	stub := eptMapResponse(tower(uuidDRSUAPI, "10.7.0.10", 49669))
	half := len(stub) / 2
	ts := dceSession(s, s.now, "10.7.0.5", 50106, "10.7.0.10", 135,
		dceStep{true, tcpBind(1, map[uint16]string{0: uuidEPM}, 0)},
		dceStep{true, tcpRequest(2, 0, 3, make([]byte, 40), 0x01, 0)}, // first fragment
		dceStep{true, tcpRequest(2, 0, 3, make([]byte, 40), 0x02, 0)}, // last fragment
		dceStep{false, dceResponse(2, stub[:half], 0x01)},
		dceStep{false, dceResponse(2, stub[half:], 0x02)})
	c := s.tcp(ts, "10.7.0.5", 50107, "10.7.0.10", 49669)
	c.Close(c.Send(ts.Add(5*time.Millisecond), true, tcpRequest(9, 0, 1, make([]byte, 16), 0x03, 0), 1400).Add(time.Millisecond))
	res := s.analyze(Config{})
	if r := rpcRow(res, "", "epmapper", "ept_map", "tcp"); r == nil || r.Count != 1 {
		t.Errorf("fragmented request counted %+v", r)
	}
	if r := rpcRow(res, "", "drsuapi", "DRSUnbind", "tcp"); r == nil {
		t.Errorf("fragmented ept_map response not reassembled: %+v", res.RPCCalls)
	}
}

// Header sniffing: a DCE/RPC stream on an odd port is parsed; non-DCE
// bytes on 135 are not.
func TestDCERPCSniff(t *testing.T) {
	if !looksDCE(tcpBind(1, map[uint16]string{0: uuidEPM}, 0), true) || looksDCE(tcpBind(1, nil, 0), false) {
		t.Error("looksDCE direction check")
	}
	if looksDCE([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), true) || looksDCE([]byte{5, 0, 0, 3, 0x10, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0}, true) {
		t.Error("looksDCE accepts junk (or a fragment shorter than its header)")
	}
	s := newSynth(t)
	c := s.tcp(s.now, "10.7.0.5", 50108, "10.7.0.10", 135)
	c.Close(c.Send(s.now.Add(5*time.Millisecond), true, []byte("hello, this is not dce/rpc at all"), 1400))
	if res := s.analyze(Config{}); len(res.RPCCalls) != 0 {
		t.Errorf("non-DCE bytes on 135 parsed: %+v", res.RPCCalls)
	}
}

func TestTowerParsers(t *testing.T) {
	tw, ok := parseTower(tower(uuidDRSUAPI, "10.1.2.3", 49668))
	if !ok || tw.uuid != uuidDRSUAPI || tw.port != 49668 || tw.ip != netip.MustParseAddr("10.1.2.3") {
		t.Fatalf("parseTower: %+v %v", tw, ok)
	}
	if got := eptMapTowers(eptMapResponse(tower(uuidDRSUAPI, "10.1.2.3", 49668), tower(uuidEPM, "10.1.2.3", 135))); len(got) != 2 || got[1].port != 135 {
		t.Fatalf("eptMapTowers: %+v", got)
	}
	b := oxidBindings(oxidStub("10.9.8.7[49999]"))
	if len(b) != 1 || b[0].port != 49999 || b[0].ip != netip.MustParseAddr("10.9.8.7") {
		t.Fatalf("oxidBindings: %+v", b)
	}
	if b := oxidBindings(oxidStub("DC01[50001]")); len(b) != 1 || b[0].ip.IsValid() || b[0].port != 50001 {
		t.Fatalf("hostname OXID binding: %+v", b)
	}
}

func FuzzDCEPDU(f *testing.F) {
	f.Add(tcpBind(1, map[uint16]string{0: uuidEPM}, 0), dceResponse(2, eptMapResponse(tower(uuidDRSUAPI, "10.0.0.1", 49668)), 0x03))
	f.Add(tcpRequest(2, 0, 3, make([]byte, 40), 0x03, 6), dceBindAck(1, []uint16{0, 2}))
	f.Fuzz(func(t *testing.T, a, b []byte) {
		e := New(Config{})
		d := newDCEState(e, "tcp", netip.MustParseAddrPort("10.0.0.1:49668"), func() string { return "unbound" }, nil)
		d.feed(a, true, time.Now(), 1)
		d.feed(b, false, time.Now(), 2)
		d.feed(append(a, b...), true, time.Now(), 3)
	})
}

func FuzzEPMTower(f *testing.F) {
	f.Add(eptMapResponse(tower(uuidDRSUAPI, "10.0.0.1", 49668)))
	f.Add(oxidStub("host[123]"))
	f.Fuzz(func(t *testing.T, b []byte) {
		parseTower(b)
		eptMapTowers(b)
		oxidBindings(b)
	})
}
