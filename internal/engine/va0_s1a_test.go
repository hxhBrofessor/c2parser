package engine

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// VA-0 S1a tests (test-first) for review findings V0-1..V0-3.

// feedPipe drives a minimal SMB2 IPC$ pipe (TreeConnect + Create [+ optional
// Write]) into a fresh engine and returns it, modelled on TestSMB2PipeTracking.
func feedPipe(t *testing.T, pipeName string, write []byte) *Engine {
	t.Helper()
	e := New(Config{})
	c := &tcpConn{ch: &channel{}}
	st := newSMBState(e, c)
	cli, srv := &smbHalf{st: st, client: true}, &smbHalf{st: st}
	ts := time.Now()
	fr := int64(1)
	next := func() int64 { fr++; return fr }
	path := u16le(`\\192.168.1.11\IPC$`)
	tc := make([]byte, 8)
	binary.LittleEndian.PutUint16(tc[0:], 9)
	binary.LittleEndian.PutUint16(tc[4:], 64+8)
	binary.LittleEndian.PutUint16(tc[6:], uint16(len(path)))
	cli.feed(nb(append(append(smb2Hdr(smbCmdTreeConnect, false, 1, 0, 0), tc...), path...)), ts, next())
	srv.feed(nb(append(smb2Hdr(smbCmdTreeConnect, true, 1, 7, 0), make([]byte, 16)...)), ts, next())
	name := u16le(pipeName)
	cr := make([]byte, 56)
	binary.LittleEndian.PutUint16(cr[0:], 57)
	binary.LittleEndian.PutUint16(cr[44:], 64+56)
	binary.LittleEndian.PutUint16(cr[46:], uint16(len(name)))
	cli.feed(nb(append(append(smb2Hdr(smbCmdCreate, false, 2, 7, 0), cr...), name...)), ts, next())
	crr := make([]byte, 88)
	binary.LittleEndian.PutUint16(crr[0:], 89)
	binary.LittleEndian.PutUint32(crr[4:], 1)
	copy(crr[64:80], bytes.Repeat([]byte{0xab}, 16))
	srv.feed(nb(append(smb2Hdr(smbCmdCreate, true, 2, 7, 0), crr...)), ts, next())
	if len(write) > 0 {
		wr := make([]byte, 48)
		binary.LittleEndian.PutUint16(wr[0:], 49)
		binary.LittleEndian.PutUint16(wr[2:], 64+48)
		binary.LittleEndian.PutUint32(wr[4:], uint32(len(write)))
		copy(wr[16:32], bytes.Repeat([]byte{0xab}, 16))
		cli.feed(nb(append(append(smb2Hdr(smbCmdWrite, false, 3, 7, 0), wr...), write...)), ts, next())
	}
	return e
}

func findCat(fs []Finding, cat string) *Finding {
	for i := range fs {
		if fs[i].Category == cat {
			return &fs[i]
		}
	}
	return nil
}

// V0-2: a finding carried only by framework-specific signals disappears in
// BLIND (with a ledger entry); a mixed finding survives at a lower score.
func TestVA0S1aExistence(t *testing.T) {
	// framework-only: a Cobalt Strike default pipe name, zero payload ->
	// only c2_default_pipe_name (framework_specific).
	e := feedPipe(t, "msagent_4f", nil)
	br := e.EvaluateBlind()
	if findCat(br.Full, string(CatPipe)) == nil {
		t.Fatal("FULL: expected a pipe finding")
	}
	if f := findCat(br.Blind, string(CatPipe)); f != nil {
		t.Errorf("BLIND: framework-only pipe finding should disappear, got score %.2f signals %v", f.Score, sigNames(f))
	}
	// ledger must record the disappearance + the suppressed signal.
	var recorded bool
	for _, en := range br.Ledger.Entries {
		if en.ExistedFull && !en.SurvivedBlind {
			for _, s := range en.Suppressed {
				if s.Name == "c2_default_pipe_name" {
					recorded = true
				}
			}
		}
	}
	if !recorded {
		t.Error("ledger did not record the framework-only finding disappearing with c2_default_pipe_name suppressed")
	}

	// mixed: same C2 default pipe name but with enough write volume to add the
	// generic pipe_volume signal -> survives in BLIND at a lower score.
	e2 := feedPipe(t, "msagent_5a", bytes.Repeat([]byte("A"), 200<<10))
	br2 := e2.EvaluateBlind()
	ff := findCat(br2.Full, string(CatPipe))
	bf := findCat(br2.Blind, string(CatPipe))
	if ff == nil || bf == nil {
		t.Fatalf("mixed pipe: FULL=%v BLIND=%v (both should exist)", ff != nil, bf != nil)
	}
	if bf.Score > ff.Score+1e-9 {
		t.Errorf("mixed pipe BLIND score %.3f should be <= FULL %.3f", bf.Score, ff.Score)
	}
	if hasSignal(bf, "c2_default_pipe_name") {
		t.Error("mixed pipe BLIND still carries framework signal c2_default_pipe_name")
	}
}

// V0-1: BLIND output carries no frame that originated from a suppressed signal,
// and no "[framework]" placeholder token anywhere. A large Havoc-framed write
// (0xDEADBEEF -> c2_framing_in_pipe, framework_specific, whose magic frames are
// the pipe finding's only frames) plus volume/randomness (generic) keeps the
// finding alive in BLIND; the magic frames must be gone.
func TestVA0S1aNoSuppressedFramesOrPlaceholder(t *testing.T) {
	var data []byte
	for i := 0; i < 1200; i++ { // ~200 KB of framed packets: survives on generic signals
		data = append(data, havocPacket(160)...)
	}
	e := feedPipe(t, "gainz", data)
	br := e.EvaluateBlind()
	full := findCat(br.Full, string(CatPipe))
	if full == nil || !hasSignal(full, "c2_framing_in_pipe") {
		t.Fatalf("FULL: expected c2_framing_in_pipe on the pipe finding: %v", full)
	}
	if len(full.Frames) == 0 {
		t.Fatalf("FULL pipe finding should carry the framing frames")
	}
	blob, _ := json.Marshal(br.Blind)
	if strings.Contains(string(blob), "[framework]") {
		t.Error("BLIND output contains the [framework] placeholder token")
	}
	bf := findCat(br.Blind, string(CatPipe))
	if bf == nil {
		t.Fatal("BLIND: pipe finding should survive on generic volume/randomness signals")
	}
	if hasSignal(bf, "c2_framing_in_pipe") {
		t.Error("BLIND pipe still carries the framework signal c2_framing_in_pipe")
	}
	// the magic frames belonged to the suppressed c2_framing_in_pipe; BLIND
	// must carry strictly fewer frames (those are dropped), while legitimate
	// generic open/first-activity frames may remain.
	fullSet := map[int64]bool{}
	for _, fr := range full.Frames {
		fullSet[fr] = true
	}
	if len(bf.Frames) >= len(full.Frames) {
		t.Errorf("BLIND pipe should drop the suppressed framing frames: full=%v blind=%v", full.Frames, bf.Frames)
	}
	for _, fr := range bf.Frames {
		if !fullSet[fr] {
			t.Errorf("BLIND pipe has frame %d not in FULL", fr)
		}
	}
	var dropped bool
	for _, en := range br.Ledger.Entries {
		for _, s := range en.Suppressed {
			if s.Name == "c2_framing_in_pipe" {
				dropped = true
			}
		}
	}
	if !dropped {
		t.Error("ledger did not record c2_framing_in_pipe suppression")
	}
}

// V0-4: pivot_frame_header detects any repeated constant 4-byte prefix with no
// attribution (frameprefix.go) and must be classed generic (retained in BLIND),
// unlike the vendor-magic c2_framing_in_pipe.
func TestVA0S1aPivotFrameHeaderGeneric(t *testing.T) {
	p := newEvidencePolicy(FrameworkBlindMode)
	if p.classify("pivot_frame_header") != classGeneric {
		t.Errorf("pivot_frame_header must be generic, got %v", p.classify("pivot_frame_header"))
	}
	if p.suppresses("pivot_frame_header") {
		t.Error("pivot_frame_header (generic) must be retained in BLIND")
	}
	if !p.suppresses("c2_framing_in_pipe") {
		t.Error("c2_framing_in_pipe (vendor magic) must stay suppressed")
	}
}

// V0-3: a finding whose category came only from suppressed evidence (a
// standalone Sigma match finding) is absent in BLIND.
func TestVA0S1aCategoryFromBlind(t *testing.T) {
	s := newSynth(t)
	// a single Havoc-default HTTP request to a host with no other evidence, so
	// the Sigma hit would otherwise stand alone as a CatSigma finding.
	ts := s.now
	ua := "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
	c := s.tcp(ts, "10.9.3.33", 52222, "203.0.113.11", 80)
	c.Send(ts.Add(time.Second), true, httpReq("POST", "/", []string{"Host: 203.0.113.11", "User-Agent: " + ua, "Content-Type: */*"}, string(randB(32))), 1400)
	c.Close(ts.Add(2 * time.Second))
	br := s.analyzeBlind(Config{Sigma: havocRule(t)})
	for _, f := range br.Blind {
		if f.Category == CatSigma {
			t.Errorf("BLIND: standalone Sigma finding (category from suppressed evidence) should be absent: %s", f.Title)
		}
	}
}

func sigNames(f *Finding) []string {
	var n []string
	for _, s := range f.Signals {
		n = append(n, s.Name)
	}
	return n
}
