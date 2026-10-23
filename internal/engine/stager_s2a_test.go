package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// S2a / S2-1: an INSPECTING tap holds a process-global probe slot. closeStagers()
// (the analyzeFile ingest-error defer and the Finish() backstop) must finalize
// INSPECTING taps too, releasing their probes — not only ADMITTED ones.
func TestStagerInspectingProbeReleasedOnClose(t *testing.T) {
	base := loadProbes()
	e := New(Config{})
	// abandon 40 inspecting taps: unknown content-type, a short non-MZ body
	// fragment with no Content-Length -> stays INSPECTING, probe held.
	var taps []*stagerTap
	for i := 0; i < 40; i++ {
		tp := e.newStagerTap(&tcpConn{}, &httpMsg{hdr: map[string]string{}})
		tp.feed([]byte("not-a-stage-"))
		taps = append(taps, tp)
	}
	held := loadProbes() - base
	if held == 0 {
		t.Fatal("no probes held by inspecting taps (test precondition failed)")
	}
	e.closeStagers()
	if got := loadProbes(); got != base {
		t.Errorf("probe slots not released by closeStagers(): got %d want baseline %d", got, base)
	}
	// a fresh MZ response must now be admitted, not refused.
	e2 := New(Config{})
	tp := e2.newStagerTap(&tcpConn{}, &httpMsg{hdr: map[string]string{"content-type": "application/octet-stream"}})
	tp.feed(plainStageFixture())
	tp.finalize(true)
	if e2.stager.resourceLimit != 0 {
		t.Errorf("fresh MZ response refused with resource_limit after closeStagers() (probe pool still saturated)")
	}
	if e2.stager.signalEmitted != 1 {
		t.Errorf("fresh MZ response did not carve/emit after release: signalEmitted=%d", e2.stager.signalEmitted)
	}
}

// S2a / S2-1: the real analyzeFile ingest-error path (truncated pcap) leaves the
// probe pool at baseline.
func TestStagerIngestErrorReleasesProbes(t *testing.T) {
	base := loadProbes()
	s := newSynth(t)
	ts := s.now
	// a response that enters INSPECTING: unknown type, huge CL, a non-MZ body
	// fragment, and never completes (no close).
	c := s.tcp(ts, "10.7.0.44", 52400, "203.0.113.44", 80)
	c.Send(ts.Add(time.Second), true, httpReq("GET", "/a", []string{"Host: 203.0.113.44"}, ""), 1400)
	head := []byte("HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n")
	c.Send(ts.Add(30*time.Millisecond), false, append(head, []byte("not-a-stage-prefix")...), 1400)
	dir := t.TempDir()
	p := filepath.Join(dir, "trunc.pcap")
	buf := s.buf.Bytes()
	// append a bogus record header with an implausible incl_len so the reader
	// returns a hard ingest error (not a clean EOF) after the inspecting
	// response has been parsed.
	bogus := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if err := os.WriteFile(p, append(append([]byte{}, buf...), bogus...), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := AnalyzeFile(p, Config{})
	if err == nil {
		t.Skip("truncated pcap did not produce an ingest error on this reader; probe-release still covered by TestStagerInspectingProbeReleasedOnClose")
	}
	if got := loadProbes(); got != base {
		t.Errorf("ingest error leaked probe slots: got %d want baseline %d", got, base)
	}
}

// S2a / S2-2: a plausible xorencoded header with no Content-Length is counted,
// not admitted.
func TestStagerXorNoClenCounter(t *testing.T) {
	e := New(Config{})
	// body that carries a valid-size wrapper header at offset 0 but is sent
	// without a Content-Length (chunked-style): size = len(decoded) >= 0x1000.
	body := xorStageFixture()
	tp := e.newStagerTap(&tcpConn{}, &httpMsg{hdr: map[string]string{}}) // no content-length
	tp.feed(body)
	tp.finalize(true)
	if e.stager.signalEmitted != 0 {
		t.Error("xorencoded without Content-Length should not be admitted/emit")
	}
	if e.StagerCounts()["xor_unadmitted_no_clen"] < 1 {
		t.Errorf("xor_unadmitted_no_clen not counted: %v", e.StagerCounts())
	}
}
