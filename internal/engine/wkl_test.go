package engine

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// Tests for the WKL-Sec-derived detections: Cobalt Strike default pipe-name
// patterns and WMI / DCOM lateral movement over DCE/RPC.

func TestClassifyPipeC2Patterns(t *testing.T) {
	// Names as classifyPipe receives them: smbFile.pipeName() lower-cases and
	// strips a leading "\" and "pipe\", but callers may pass original case.
	hits := []struct{ name, want string }{
		{`winsock2\catalogchangelistener-a3f-0`, "CatalogChangeListener"},
		{`Winsock2\CatalogChangeListener-123-0`, "CatalogChangeListener"},
		{`tsvcpipe-1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d`, "TSVCPIPE"},
		{`TSVCPIPE-DEADBEEF-0000-1111-2222-333344445555`, "TSVCPIPE"},
		{`local\cubeb-pipe-1a2b-3`, "SSH pipe"},
		{`cubeb-pipe-99-1`, "SSH pipe"},
		{`postex_1a2b`, "post-ex"},
		{`postex_ssh_beef`, "post-ex"},
		{`msagent_4f`, "msagent_"},
		{`jaccdpqnvbrrxlaf`, "jaccdpqnvbrrxlaf"},
		{`gruntsvc`, "gruntsvc"},
	}
	for _, h := range hits {
		known, c2 := classifyPipe(h.name)
		if known || !strings.Contains(c2, h.want) {
			t.Errorf("classifyPipe(%q) = (%v, %q), want C2 match containing %q", h.name, known, c2, h.want)
		}
	}
	// Near misses: must not be labelled by a CS pattern. (Some still hit a
	// prefix rule, so check the pattern label only.)
	misses := []string{
		`winsock2\catalog_change_listener`,                    // genuine Windows pipe
		`winsock2\catalogchangelistener-xyz-0`,                // non-hex
		`tsvcpipe-1a2b3c4d-5e6f-7a8b-9c0d`,                    // truncated UUID
		`tsvcpipe-1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d-extra`, // trailing junk
		`xcubeb-pipe-1-2`,                                     // anchored
		`postex_zz`,                                           // non-hex suffix
		`msagent_123456`,                                      // too long
	}
	for _, m := range misses {
		for _, p := range c2PipePatterns {
			if p.re.MatchString(m) {
				t.Errorf("pattern %q matched near-miss %q", p.name, m)
			}
		}
	}
	if known, c2 := classifyPipe(`winsock2\catalog_change_listener`); !known || c2 != "" {
		t.Errorf("genuine Windows pipe misclassified: known=%v c2=%q", known, c2)
	}
}

// ------------------------------------------------------------ DCE/RPC

// uuidBytesLE encodes a canonical UUID string in DCE/RPC (little-endian
// first three fields) wire order.
func uuidBytesLE(t *testing.T, u string) []byte {
	raw, err := hex.DecodeString(strings.ReplaceAll(u, "-", ""))
	if err != nil || len(raw) != 16 {
		t.Fatalf("bad uuid %q", u)
	}
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b, binary.BigEndian.Uint32(raw))
	binary.LittleEndian.PutUint16(b[4:], binary.BigEndian.Uint16(raw[4:]))
	binary.LittleEndian.PutUint16(b[6:], binary.BigEndian.Uint16(raw[6:]))
	copy(b[8:], raw[8:])
	return b
}

const ndrTransferSyntax = "8a885d04-1ceb-11c9-9fe8-08002b104860"

func dceBind(t *testing.T, ctxID uint16, iface string) []byte {
	p := make([]byte, 28)
	p[0], p[1], p[2], p[3] = 5, 0, 11, 0x03 // v5.0 bind, first|last frag
	p[4] = 0x10                             // little-endian data rep
	binary.LittleEndian.PutUint32(p[12:], 1)
	binary.LittleEndian.PutUint16(p[16:], 4280)
	binary.LittleEndian.PutUint16(p[18:], 4280)
	p[24] = 1 // one context item
	ctx := make([]byte, 4)
	binary.LittleEndian.PutUint16(ctx, ctxID)
	ctx[2] = 1 // one transfer syntax
	ctx = append(ctx, uuidBytesLE(t, iface)...)
	ctx = append(ctx, 0, 0, 0, 0) // interface version
	ctx = append(ctx, uuidBytesLE(t, ndrTransferSyntax)...)
	ctx = append(ctx, 2, 0, 0, 0)
	p = append(p, ctx...)
	binary.LittleEndian.PutUint16(p[8:], uint16(len(p)))
	return p
}

func dceRequest(ctxID, opnum uint16, stub []byte) []byte {
	p := make([]byte, 24)
	p[0], p[1], p[2], p[3] = 5, 0, 0, 0x03
	p[4] = 0x10
	binary.LittleEndian.PutUint32(p[12:], 2)
	binary.LittleEndian.PutUint32(p[16:], uint32(len(stub)))
	binary.LittleEndian.PutUint16(p[20:], ctxID)
	binary.LittleEndian.PutUint16(p[22:], opnum)
	p = append(p, stub...)
	binary.LittleEndian.PutUint16(p[8:], uint16(len(p)))
	return p
}

// smbPipeSession writes a pcap with TCP/445 from client to server: tree
// connect to IPC$, CREATE of pipeName, then one SMB2 WRITE per payload.
func smbPipeSession(t *testing.T, s *synth, client, server, pipeName string, payloads ...[]byte) {
	ts := s.now
	sess := s.tcp(ts, client, 49700, server, 445)
	step := func(d time.Duration, fromClient bool, msg []byte) {
		ts = ts.Add(d)
		sess.Send(ts, fromClient, nb(msg), 1400)
	}
	const tree = 5
	fid := bytes.Repeat([]byte{0xcd}, 16)

	path := u16le(`\\` + server + `\IPC$`)
	tc := make([]byte, 8)
	binary.LittleEndian.PutUint16(tc[0:], 9)
	binary.LittleEndian.PutUint16(tc[4:], 64+8)
	binary.LittleEndian.PutUint16(tc[6:], uint16(len(path)))
	step(time.Millisecond, true, append(append(smb2Hdr(smbCmdTreeConnect, false, 1, 0, 0), tc...), path...))
	step(time.Millisecond, false, append(smb2Hdr(smbCmdTreeConnect, true, 1, tree, 0), make([]byte, 16)...))

	name := u16le(pipeName)
	cr := make([]byte, 56)
	binary.LittleEndian.PutUint16(cr[0:], 57)
	binary.LittleEndian.PutUint16(cr[44:], 64+56)
	binary.LittleEndian.PutUint16(cr[46:], uint16(len(name)))
	step(time.Millisecond, true, append(append(smb2Hdr(smbCmdCreate, false, 2, tree, 0), cr...), name...))
	crr := make([]byte, 88)
	binary.LittleEndian.PutUint16(crr[0:], 89)
	binary.LittleEndian.PutUint32(crr[4:], 1) // FILE_OPENED
	copy(crr[64:80], fid)
	step(time.Millisecond, false, append(smb2Hdr(smbCmdCreate, true, 2, tree, 0), crr...))

	for i, data := range payloads {
		wr := make([]byte, 48)
		binary.LittleEndian.PutUint16(wr[0:], 49)
		binary.LittleEndian.PutUint16(wr[2:], 64+48)
		binary.LittleEndian.PutUint32(wr[4:], uint32(len(data)))
		copy(wr[16:32], fid)
		step(10*time.Millisecond, true, append(append(smb2Hdr(smbCmdWrite, false, uint64(3+i), tree, 0), wr...), data...))
	}
	sess.Close(ts.Add(time.Second))
}

func lateralFindings(res *Result) []*Finding {
	var out []*Finding
	for i := range res.Findings {
		if res.Findings[i].Category == CatLateral {
			out = append(out, &res.Findings[i])
		}
	}
	return out
}

func TestDCERPCWMIExecMethodOverPipe(t *testing.T) {
	s := newSynth(t)
	smbPipeSession(t, s, "10.20.0.5", "10.20.0.10", "wmi_lm",
		dceBind(t, 0, "9556dc99-828c-11cf-a37e-00aa003240c7"), // IWbemServices
		dceRequest(0, 24, randB(64)),                          // ExecMethod
	)
	res := s.analyze(Config{})
	lat := lateralFindings(res)
	if len(lat) != 1 {
		t.Fatalf("want 1 lateral finding, got %d: %+v", len(lat), res.Findings)
	}
	if !hasSignal(lat[0], "rpc:IWbemServices:ExecMethod") {
		t.Errorf("missing rpc:IWbemServices:ExecMethod signal: %+v", lat[0].Signals)
	}
	if lat[0].Client != "10.20.0.5" || lat[0].Server != "10.20.0.10" {
		t.Errorf("endpoints %s → %s", lat[0].Client, lat[0].Server)
	}
}

func TestDCERPCDCOMActivationOverPipe(t *testing.T) {
	s := newSynth(t)
	smbPipeSession(t, s, "10.20.0.6", "10.20.0.11", "dcom_lm",
		dceBind(t, 1, "000001a0-0000-0000-c000-000000000046"), // IRemoteSCMActivator
		dceRequest(1, 4, randB(32)),                           // RemoteCreateInstance
	)
	res := s.analyze(Config{})
	lat := lateralFindings(res)
	if len(lat) != 1 || !hasSignal(lat[0], "rpc:IRemoteSCMActivator:RemoteCreateInstance") {
		t.Fatalf("DCOM activation not flagged: %+v", lat)
	}
}

func TestDCERPCBenignSrvsvcNoLateral(t *testing.T) {
	s := newSynth(t)
	smbPipeSession(t, s, "10.20.0.7", "10.20.0.12", "srvsvc",
		dceBind(t, 0, "4b324fc8-1670-01d3-1278-5a47bf6ee188"), // srvsvc
		dceRequest(0, 15, randB(48)),                          // NetrShareEnumAll
	)
	res := s.analyze(Config{})
	if lat := lateralFindings(res); len(lat) != 0 {
		t.Fatalf("benign srvsvc share enum produced lateral finding(s): %+v", lat[0])
	}
	if f := findBy(res, CatPipe, "srvsvc"); f != nil && hasSignal(f, "unrecognised_pipe") {
		t.Errorf("srvsvc flagged as unrecognised pipe: %+v", f.Signals)
	}
}

// v9 Phase 1.2: DCE/RPC calls are exposed in JSON.
func TestRPCCallsJSON(t *testing.T) {
	s := newSynth(t)
	smbPipeSession(t, s, "10.20.0.8", "10.20.0.13", "wmi_lm2",
		dceBind(t, 0, "9556dc99-828c-11cf-a37e-00aa003240c7"),
		dceRequest(0, 24, randB(64)),
		dceRequest(0, 24, randB(64)),
		dceRequest(3, 7, randB(16)), // context 3 never bound
	)
	res := s.analyze(Config{})
	var exec, unbound *RPCCall
	for i := range res.RPCCalls {
		c := &res.RPCCalls[i]
		switch {
		case c.Endpoint == "IWbemServices" && c.Op == "ExecMethod":
			exec = c
		case !c.Bound:
			unbound = c
		}
	}
	if exec == nil || exec.Count != 2 || !exec.Bound || exec.Transport != "smb-pipe" || len(exec.Pipes) != 1 || exec.Pipes[0] != "wmi_lm2" || exec.FirstFrame == 0 || exec.LastFrame <= exec.FirstFrame || exec.Client != "10.20.0.8" {
		t.Errorf("ExecMethod call: %+v (all %+v)", exec, res.RPCCalls)
	}
	if unbound == nil || unbound.Endpoint != "wmi_lm2" || unbound.Op != "opnum_7" {
		t.Errorf("unbound call: %+v", unbound)
	}
}

// v9 Phase 1.2: an info-level HTTP channel is titled "HTTP channel", not "HTTP C2".
func TestBenignHTTPTitle(t *testing.T) {
	s := newSynth(t)
	ts := s.now
	c := s.tcp(ts, "10.20.0.9", 52200, "203.0.113.120", 80)
	for i := 0; i < 5; i++ {
		hdr := []string{"Host: ocsp.example", "Accept: */*", "Accept-Encoding: gzip", "Accept-Language: en"}
		if i >= 2 {
			hdr = append(hdr, "User-Agent: Microsoft-CryptoAPI/10.0")
		}
		ts = c.Send(ts.Add(time.Duration(7+i*13)*time.Second), true, httpReq("GET", "/ocsp", hdr, ""), 1400)
		ts = c.Send(ts.Add(30*time.Millisecond), false, httpResp("HTTP/1.1 200 OK", []string{"Content-Type: application/ocsp-response"}, "ok"), 1400)
	}
	c.Close(ts.Add(time.Second))
	res := s.analyze(Config{})
	seen := false
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "203.0.113.120") {
			seen = true
			if f.Score < 0.2 && !strings.HasPrefix(f.Title, "HTTP channel ") {
				t.Errorf("info-level channel title %q (%.2f)", f.Title, f.Score)
			}
		}
	}
	if !seen {
		t.Fatal("expected an info-level finding for the channel")
	}
}

// rev 2 Phase 0.2: one rpc_calls row per (client, server, endpoint, op,
// transport) across pipe opens and SMB sessions, counts summed.
func TestRPCCallsAggregated(t *testing.T) {
	s := newSynth(t)
	for i := 0; i < 3; i++ {
		smbPipeSession(t, s, "10.20.0.30", "10.20.0.31", "lsm_api_service",
			dceBind(t, 0, "484809d6-4239-471b-b5bc-61df8c23ac48"),
			dceRequest(0, 0, randB(16)))
		s.now = s.now.Add(time.Minute)
	}
	res := s.analyze(Config{})
	n := 0
	for _, c := range res.RPCCalls {
		if c.Server == "10.20.0.31" {
			n++
			if c.Count != 3 || c.Op != "opnum_0" {
				t.Errorf("aggregated row %+v, want count 3", c)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d rows for one (client, server, endpoint, op), want 1: %+v", n, res.RPCCalls)
	}
}
