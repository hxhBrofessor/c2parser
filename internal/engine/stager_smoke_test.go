package engine

import (
	"testing"
	"time"

	"c2parser/internal/csconfig"
)

// round-trip: the replicated fixtures must be accepted by the real carver, and
// be evidence-sufficient, so the engine-tap tests rest on honest bytes.
func TestStagerFixturesCarve(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
	}{{"plain", plainStageFixture()}, {"xor", xorStageFixture()}} {
		c := csconfig.New(csconfig.Options{})
		c.Feed(tc.body)
		cfg, ok := c.Result()
		if !ok {
			t.Fatalf("%s: carver rejected fixture: reason=%s", tc.name, c.Reason())
		}
		if _, suff := stagerSufficient(cfg); !suff {
			t.Fatalf("%s: fixture not evidence-sufficient", tc.name)
		}
	}
}

// respWithBody sends one GET + an octet-stream response carrying body, on its
// own connection, and analyzes.
func stagerScenario(t *testing.T, server string, ctype string, body []byte) *Result {
	t.Helper()
	s := newSynth(t)
	ts := s.now
	c := s.tcp(ts, "10.7.0.5", 50500, server, 80)
	ts = c.Send(ts.Add(time.Second), true, httpReq("GET", "/a", []string{"Host: " + server}, ""), 1400)
	ts = c.Send(ts.Add(30*time.Millisecond), false, httpResp("HTTP/1.1 200 OK", []string{"Content-Type: " + ctype}, string(body)), 1400)
	c.Close(ts.Add(time.Second))
	return s.analyze(Config{})
}

func hasStagerSignal(res *Result, server string) bool {
	for _, f := range res.Findings {
		if f.Server != server {
			continue
		}
		for _, sg := range f.Signals {
			if sg.Name == stagerSignalName {
				return true
			}
		}
	}
	return false
}

func TestStagerPlainAndXorEmitSignal(t *testing.T) {
	if !hasStagerSignal(stagerScenario(t, "203.0.113.50", "application/octet-stream", plainStageFixture()), "203.0.113.50") {
		t.Error("plain MZ stage did not emit cs_config:beacon_config")
	}
	if !hasStagerSignal(stagerScenario(t, "203.0.113.51", "application/octet-stream", xorStageFixture()), "203.0.113.51") {
		t.Error("xorencoded stage did not emit cs_config:beacon_config")
	}
}
