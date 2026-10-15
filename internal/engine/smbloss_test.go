package engine

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// Stress-test finding 7: with packet loss, a pipe's CREATE or READ request
// can be lost, so its data lands on an unnamed FileId or the zero-FileId
// bucket. That must not become extra "opened before capture" findings.
func TestSMBLostNamingRequestsMerge(t *testing.T) {
	s := newSynth(t)
	ts := s.now
	sess := s.tcp(ts, "10.6.0.32", 49800, "10.6.0.11", 445)
	step := func(fromClient bool, msg []byte) {
		ts = ts.Add(500 * time.Millisecond)
		sess.Send(ts, fromClient, nb(msg), 1400)
	}
	const tree = 9
	path := u16le(`\\10.6.0.11\IPC$`)
	tc := make([]byte, 8)
	binary.LittleEndian.PutUint16(tc[0:], 9)
	binary.LittleEndian.PutUint16(tc[4:], 64+8)
	binary.LittleEndian.PutUint16(tc[6:], uint16(len(path)))
	step(true, append(append(smb2Hdr(smbCmdTreeConnect, false, 1, 0, 0), tc...), path...))
	step(false, append(smb2Hdr(smbCmdTreeConnect, true, 1, tree, 0), make([]byte, 16)...))

	createResp := func(mid uint64, fid []byte) []byte {
		crr := make([]byte, 88)
		binary.LittleEndian.PutUint16(crr[0:], 89)
		binary.LittleEndian.PutUint32(crr[4:], 1)
		copy(crr[64:80], fid)
		return append(smb2Hdr(smbCmdCreate, true, mid, tree, 0), crr...)
	}
	write := func(mid uint64, fid, data []byte) []byte {
		wr := make([]byte, 48)
		binary.LittleEndian.PutUint16(wr[0:], 49)
		binary.LittleEndian.PutUint16(wr[2:], 64+48)
		binary.LittleEndian.PutUint32(wr[4:], uint32(len(data)))
		copy(wr[16:32], fid)
		return append(append(smb2Hdr(smbCmdWrite, false, mid, tree, 0), wr...), data...)
	}
	fidA, fidB := bytes.Repeat([]byte{0xa1}, 16), bytes.Repeat([]byte{0xb2}, 16)

	// open A: CREATE request + response both captured
	name := u16le("gainz")
	cr := make([]byte, 56)
	binary.LittleEndian.PutUint16(cr[0:], 57)
	binary.LittleEndian.PutUint16(cr[44:], 64+56)
	binary.LittleEndian.PutUint16(cr[46:], uint16(len(name)))
	step(true, append(append(smb2Hdr(smbCmdCreate, false, 2, tree, 0), cr...), name...))
	step(false, createResp(2, fidA))
	for i := 0; i < 6; i++ {
		step(true, write(uint64(10+i), fidA, havocPacket(80)))
	}
	// open B: CREATE request lost → response alone, FileId unnamed
	step(false, createResp(3, fidB))
	for i := 0; i < 6; i++ {
		step(true, write(uint64(20+i), fidB, havocPacket(80)))
	}
	// READ response whose request was lost → zero-FileId bucket
	out := havocPacket(120)
	rr := make([]byte, 16)
	binary.LittleEndian.PutUint16(rr[0:], 17)
	rr[2] = 64 + 16
	binary.LittleEndian.PutUint32(rr[4:], uint32(len(out)))
	step(false, append(append(smb2Hdr(smbCmdRead, true, 99, tree, 0), rr...), out...))
	sess.Close(ts.Add(time.Second))

	for _, cfg := range []Config{{}, {TimingV2: true}} {
		res := s.analyze(cfg)
		pipes := 0
		for _, f := range res.Findings {
			if strings.Contains(f.Title, "opened before capture") || strings.Contains(f.Title, "fid=") {
				t.Errorf("v2=%v: split finding %q (%.2f)", cfg.TimingV2, f.Title, f.Score)
			}
			if f.Category == CatPipe && strings.Contains(f.Title, "gainz") {
				pipes++
			}
		}
		if pipes != 1 {
			t.Errorf("v2=%v: %d gainz findings, want 1", cfg.TimingV2, pipes)
		}
		var row *SMBFileSummary
		for i := range res.Pipes {
			if res.Pipes[i].Name == "gainz" {
				row = &res.Pipes[i]
			}
		}
		if row == nil || row.Opens != 3 || row.Writes != 12 || row.ReadBytes != int64(len(out)) {
			t.Errorf("v2=%v: merged summary %+v", cfg.TimingV2, row)
		}
	}
}
