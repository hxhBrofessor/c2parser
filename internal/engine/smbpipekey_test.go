package engine

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"
)

// FIX-D2: one smbState per TCP connection, but the smb_pipe timing key had
// no ports, so the same pipe over several connections between one host
// pair produced repeated identical keys.

// smbPipeConn is smbPipeSession with a chosen client port and start time.
func smbPipeConn(s *synth, client string, cport uint16, server, pipeName string, start time.Time, payloads ...[]byte) {
	ts := start
	sess := s.tcp(ts, client, cport, server, 445)
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
		step(10*time.Second, true, append(append(smb2Hdr(smbCmdWrite, false, uint64(3+i), tree, 0), wr...), data...))
	}
	sess.Close(ts.Add(time.Second))
}

func pipeSeries(res *Result) []TimingSeries {
	var out []TimingSeries
	for _, ts := range res.Timing {
		if ts.Site == "smb_pipe" {
			out = append(out, ts)
		}
	}
	return out
}

func distinctKeys(ss []TimingSeries) int {
	m := map[string]bool{}
	for _, ts := range ss {
		m[ts.Key] = true
	}
	return len(m)
}

// checkPipeKeys: 3 smb_pipe entries with 3 distinct keys, the same in all
// runs, and one pipe finding under the unchanged address-only finding key.
func checkPipeKeys(t *testing.T, s *synth) []TimingSeries {
	t.Helper()
	_, rs := analyzeRuns(t, s, Config{TimingV2: true}, 10)
	var first []byte
	var ps0 []TimingSeries
	for i, res := range rs {
		ps := pipeSeries(res)
		t.Logf("run %d: %d smb_pipe entries, %d distinct keys", i, len(ps), distinctKeys(ps))
		if len(ps) != 3 || distinctKeys(ps) != 3 {
			t.Fatalf("run %d: %d smb_pipe entries with %d distinct keys, want 3 and 3", i, len(ps), distinctKeys(ps))
		}
		b, _ := json.Marshal(ps)
		if i == 0 {
			first, ps0 = b, ps
		} else if !bytes.Equal(b, first) {
			t.Fatalf("run %d: smb_pipe series differ from run 0", i)
		}
		n := 0
		for _, f := range res.Findings {
			if f.Category == CatPipe {
				n++
				if f.Title != "Named pipe "+`\\10.7.0.20\IPC$\beacon_conn`+" on 10.7.0.20 (client 10.7.0.10)" {
					t.Errorf("run %d: pipe finding title %q", i, f.Title)
				}
			}
		}
		if n != 1 {
			t.Fatalf("run %d: %d pipe findings, want 1", i, n)
		}
	}
	return ps0
}

// T-D2a
func TestSMBPipeTimingKeysUnique(t *testing.T) {
	s := newSynth(t)
	for c := 0; c < 3; c++ {
		var payloads [][]byte
		for i := 0; i < 8+c; i++ {
			payloads = append(payloads, randB(64+16*c))
		}
		smbPipeConn(s, "10.7.0.10", uint16(49700+c), "10.7.0.20", "beacon_conn", s.now.Add(time.Duration(c)*time.Minute), payloads...)
	}
	ps := checkPipeKeys(t, s)
	for _, ts := range ps {
		t.Logf("key %s", ts.Key)
	}
}

// T-D2b: identical I/O on each connection is not deduplicated; the entries
// differ only in the key.
func TestSMBPipeTimingKeysIdenticalIO(t *testing.T) {
	s := newSynth(t)
	var payloads [][]byte
	for i := 0; i < 8; i++ {
		payloads = append(payloads, randB(64))
	}
	for c := 0; c < 3; c++ {
		smbPipeConn(s, "10.7.0.10", uint16(49700+c), "10.7.0.20", "beacon_conn", s.now, payloads...)
	}
	ps := checkPipeKeys(t, s)
	var ref []byte
	for i, ts := range ps {
		ts.Key = ""
		b, _ := json.Marshal(ts)
		if i == 0 {
			ref = b
		} else if !bytes.Equal(b, ref) {
			t.Errorf("entry %d differs from entry 0 apart from the key:\n%s\n%s", i, b, ref)
		}
	}
}
