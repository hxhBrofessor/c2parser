package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

func ledgerHas(br *BlindResult, sig, class string) bool {
	for _, e := range br.Ledger.Entries {
		for _, s := range e.Suppressed {
			if s.Name == sig && s.Class == class {
				return true
			}
		}
	}
	return false
}

// V1a-2: exact exclusion — the FULL pipe finding's c2_framing_in_pipe frames do
// not appear in BLIND, the ledger records frames_dropped, and BLIND frames are
// a subset of FULL (legitimate generic open/activity frames may remain).
func TestVA0S1bFramingFramesExcluded(t *testing.T) {
	var data []byte
	for i := 0; i < 1200; i++ {
		data = append(data, havocPacket(160)...)
	}
	e := feedPipe(t, "gainz", data)
	br := e.EvaluateBlind()
	full := findCat(br.Full, string(CatPipe))
	bf := findCat(br.Blind, string(CatPipe))
	if full == nil || bf == nil || !hasSignal(full, "c2_framing_in_pipe") {
		t.Fatalf("expected FULL+BLIND pipe findings with c2_framing_in_pipe in FULL")
	}
	blindSet := map[int64]bool{}
	for _, fr := range bf.Frames {
		blindSet[fr] = true
	}
	dropped := 0
	for _, fr := range full.Frames {
		if !blindSet[fr] {
			dropped++
		}
	}
	if dropped == 0 {
		t.Errorf("no frames excluded in BLIND; c2_framing_in_pipe frames should be dropped (full=%v blind=%v)", full.Frames, bf.Frames)
	}
	for _, fr := range bf.Frames {
		found := false
		for _, ff := range full.Frames {
			if ff == fr {
				found = true
			}
		}
		if !found {
			t.Errorf("BLIND frame %d not present in FULL", fr)
		}
	}
	if !ledgerHas(br, "c2_framing_in_pipe", "frames_dropped") {
		t.Error("ledger must record frames_dropped for c2_framing_in_pipe")
	}
}

// (c) BLIND text scan: no surviving BLIND evidence line echoes content that
// belongs to a suppressed signal (framework names or framework fingerprint
// bytes), cross-checked against the ledger drop record.
func TestVA0S1bNoSuppressedContentInBlindEvidence(t *testing.T) {
	var data []byte
	for i := 0; i < 1200; i++ {
		data = append(data, havocPacket(160)...)
	}
	e := feedPipe(t, "gainz", data)
	br := e.EvaluateBlind()
	// the magic framing bytes (0xDEADBEEF) belong to the suppressed
	// c2_framing_in_pipe; they must not appear in any BLIND evidence line.
	for _, f := range br.Blind {
		for _, ev := range f.Evidence {
			low := strings.ToLower(ev)
			if strings.Contains(low, "deadbeef") || strings.Contains(low, "havoc") || strings.Contains(low, "demon framing") {
				t.Errorf("BLIND evidence echoes suppressed-signal content: %q", ev)
			}
		}
	}
	if !ledgerHas(br, "c2_framing_in_pipe", "frames_dropped") {
		t.Error("ledger cross-check: expected frames_dropped for c2_framing_in_pipe")
	}
	// the Havoc HTTP fixture: the suppressed sigma + default-UA signals must
	// leave no framework name in BLIND evidence.
	s := newSynth(t)
	havocHTTP(s)
	br2 := s.analyzeBlind(Config{Sigma: havocRule(t)})
	pol := newEvidencePolicy(FrameworkBlindMode)
	blob, _ := json.Marshal(br2.Blind)
	low := strings.ToLower(string(blob))
	for _, n := range pol.frameworkNames() {
		if strings.Contains(low, strings.ToLower(n)) {
			t.Errorf("BLIND output names framework %q", n)
		}
	}
}
