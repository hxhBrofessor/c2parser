package engine

import (
	"bytes"
	"testing"
	"time"
)

func TestReuseHTTPParsesSecondRequest(t *testing.T) {
	s := newSynth(t)
	first := s.tcp(s.now, "10.8.0.5", 50100, "10.8.0.20", 80)
	first.Send(s.now.Add(time.Millisecond), true, httpReq("GET", "/first", []string{"Host: reuse.example"}, ""), 1400)
	secondStart := s.now.Add(5 * time.Minute)
	second := s.tcp(secondStart, "10.8.0.5", 50100, "10.8.0.20", 80)
	second.Send(secondStart.Add(time.Millisecond), true, httpReq("GET", "/second", []string{"Host: reuse.example"}, ""), 1400)
	res := s.analyze(Config{RecordConns: true})
	if len(res.Conns) != 2 || res.Counters.HTTPMessages != 2 {
		t.Fatalf("TCP connections=%d HTTP messages=%d, want 2/2", len(res.Conns), res.Counters.HTTPMessages)
	}
}

func TestReuseRetransmissionOnLiveConnectionNotNewConnection(t *testing.T) {
	s := newSynth(t)
	conn := s.tcp(s.now, "10.8.0.5", 50101, "10.8.0.20", 80)
	conn.Retransmit = true
	conn.Send(s.now.Add(time.Millisecond), true, httpReq("GET", "/once", []string{"Host: reuse.example"}, ""), 1400)
	res := s.analyze(Config{RecordConns: true})
	if len(res.Conns) != 1 || res.Counters.HTTPMessages != 1 {
		t.Fatalf("duplicate segment created/altered connection: connections=%d HTTP messages=%d, want 1/1", len(res.Conns), res.Counters.HTTPMessages)
	}
}

func TestReuseIdleBelowThresholdContinuesConnection(t *testing.T) {
	s := newSynth(t)
	conn := s.tcp(s.now, "10.8.0.5", 50102, "10.8.0.20", 80)
	conn.Send(s.now.Add(time.Millisecond), true, httpReq("GET", "/first", []string{"Host: reuse.example"}, ""), 1400)
	conn.Send(s.now.Add(29*time.Second), true, httpReq("GET", "/second", []string{"Host: reuse.example"}, ""), 1400)
	res := s.analyze(Config{RecordConns: true})
	if len(res.Conns) != 1 || res.Counters.HTTPMessages != 2 {
		t.Fatalf("idle continuation split or lost data: connections=%d HTTP messages=%d, want 1/2", len(res.Conns), res.Counters.HTTPMessages)
	}
}

func TestReuseDeterminismV1AndV2(t *testing.T) {
	s := newSynth(t)
	payloads := make([][]byte, 8)
	for i := range payloads {
		payloads[i] = bytes.Repeat([]byte{byte(i + 1)}, 64)
	}
	smbPipeConnNoFinWithISND2R(s, "10.7.0.5", 50001, "10.7.0.11", "reuse_pipe", s.now, 1000, 9000, payloads...)
	smbPipeConnNoFinWithISND2R(s, "10.7.0.5", 50001, "10.7.0.11", "reuse_pipe", s.now.Add(5*time.Minute), 1000, 9000, payloads...)
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		got, results := analyzeRuns(t, s, cfg, 10)
		for i := 1; i < len(got); i++ {
			if !bytes.Equal(got[0], got[i]) {
				t.Fatalf("timing v2=%v run %d differs byte-for-byte from run 0", cfg.TimingV2, i)
			}
		}
		if cfg.TimingV2 && (len(pipeSeries(results[0])) != 2 || distinctKeys(pipeSeries(results[0])) != 2) {
			t.Fatalf("timing v2 output lost reuse observations: series=%d distinct=%d", len(pipeSeries(results[0])), distinctKeys(pipeSeries(results[0])))
		}
	}
}
