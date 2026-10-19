package engine

import (
	mrand "math/rand/v2"
	"strings"
	"testing"
	"time"
)

// schedulerHTTP writes n plain-HTTP check-ins whose gaps come from gap(),
// with benign-looking headers (or the given UA).
func schedulerHTTP(s *synth, client, server, host, ua string, n int, gap func() float64) {
	ts := s.now
	c := s.tcp(ts, client, 54000, server, 80)
	for i := 0; i < n; i++ {
		ts = ts.Add(time.Duration(gap() * float64(time.Second)))
		ts = c.Send(ts, true, httpReq("GET", "/checkin", []string{"Host: " + host, "User-Agent: " + ua, "Accept: */*", "Accept-Encoding: gzip", "Accept-Language: en-US"}, ""), 1400)
		ts = c.Send(ts.Add(50*time.Millisecond), false, httpResp("HTTP/1.1 204 No Content", nil, ""), 1400)
	}
	c.Close(ts.Add(time.Second))
}

// v9 Phase 1.3 gate: benign schedulers with no non-timing evidence stay
// below medium under both engines; the same timing plus real evidence
// (a default C2 User-Agent) is not capped.
func TestSchedulerFindingGate(t *testing.T) {
	r := mrand.New(mrand.NewPCG(31, 31))
	scheds := []struct {
		name, server string
		n            int
		gap          func() float64
	}{
		{"jamf 15±5 min", "198.51.100.61", 40, func() float64 { return 900 + 600*(r.Float64()-0.5) }},
		{"gpo 90+0–30 min", "198.51.100.62", 30, func() float64 { return 5400 + 1800*r.Float64() }},
		{"wsus 22 h × 80–100 %", "198.51.100.63", 20, func() float64 { return 79200 * (0.8 + 0.2*r.Float64()) }},
		{"chrony-like 1024 s ×U(1,1.02)", "198.51.100.64", 40, func() float64 { return 1024 * (1 + 0.02*r.Float64()) }},
	}
	for _, sc := range scheds {
		s := newSynth(t)
		schedulerHTTP(s, "10.30.0.5", sc.server, "mgmt.example", "ManagementAgent/4.2", sc.n, sc.gap)
		for _, cfg := range []Config{{}, {TimingV2: true}} {
			res := s.analyze(cfg)
			f := findBy(res, CatC2, sc.server)
			if f == nil {
				continue
			}
			if f.Score >= 0.4 {
				t.Errorf("%s v2=%v: timing-only scheduler scored %.2f (want < 0.4): %+v", sc.name, cfg.TimingV2, f.Score, f.Signals)
			}
		}
	}
	// positive control: Jamf timing + Havoc's default User-Agent
	s := newSynth(t)
	havoc := "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
	schedulerHTTP(s, "10.30.0.6", "198.51.100.65", "mgmt.example", havoc, 40, func() float64 { return 900 + 600*(r.Float64()-0.5) })
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		f := findBy(s.analyze(cfg), CatC2, "198.51.100.65")
		if f == nil || f.Score < 0.4 {
			t.Errorf("v2=%v: periodic + default-UA evidence capped: %+v", cfg.TimingV2, f)
		}
	}
}

// The v2 detail names the scheduler shape it matches (annotation only).
func TestSchedulerShapeAnnotation(t *testing.T) {
	r := mrand.New(mrand.NewPCG(32, 32))
	s := newSynth(t)
	schedulerHTTP(s, "10.30.0.7", "198.51.100.66", "mgmt.example", "ManagementAgent/4.2", 30, func() float64 { return 5400 + 1800*r.Float64() })
	f := findBy(s.analyze(Config{TimingV2: true}), CatC2, "198.51.100.66")
	if f == nil || !strings.Contains(strings.Join([]string{f.Signals[0].Detail}, ""), "Group Policy") {
		t.Errorf("GPO shape not annotated: %+v", f)
	}
}
