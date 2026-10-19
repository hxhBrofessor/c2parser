package engine

import (
	"encoding/json"
	mrand "math/rand/v2"
	"strings"
	"testing"
	"time"

	"c2parser/internal/stats"
)

// Tests for the v8 statistics engine behind -timing v2.

func seriesBy(res *Result, site, keyPart string) *TimingSeries {
	for i := range res.Timing {
		if res.Timing[i].Site == site && strings.Contains(res.Timing[i].Key, keyPart) {
			return &res.Timing[i]
		}
	}
	return nil
}

// A periodic HTTP check-in (60 s, shortening 30 %) with 50 requests.
func periodicHTTP(s *synth, client, server, host string, n int, seed uint64) {
	r := mrand.New(mrand.NewPCG(seed, seed))
	ts := s.now
	c := s.tcp(ts, client, 51500, server, 80)
	for i := 0; i < n; i++ {
		ts = ts.Add(time.Duration(60 * (1 - 0.3*r.Float64()) * float64(time.Second)))
		ts = c.Send(ts, true, httpReq("GET", "/api/v2/status", []string{"Host: " + host, "User-Agent: updater/1.0", "Accept: */*"}, ""), 1400)
		ts = c.Send(ts.Add(40*time.Millisecond), false, httpResp("HTTP/1.1 200 OK", []string{"Content-Type: application/json"}, `{"ok":true}`), 1400)
	}
	c.Close(ts.Add(time.Second))
}

// Default (v1) output carries no v2 fields: -timing v1 is unchanged from v6.
func TestTimingV1Unchanged(t *testing.T) {
	s := newSynth(t)
	periodicHTTP(s, "10.5.0.10", "203.0.113.70", "status.example", 50, 1)
	res := s.analyze(Config{})
	if res.TimingMode != "" || len(res.Timing) != 0 {
		t.Fatalf("v1 result has v2 fields: mode %q, %d series", res.TimingMode, len(res.Timing))
	}
	f := findBy(res, CatC2, "203.0.113.70")
	if f == nil || !hasSignal(f, "beacon_timing") || f.Families != nil {
		t.Fatalf("v1 finding: %+v", f)
	}
	for _, sg := range f.Signals {
		if sg.Family != "" {
			t.Errorf("v1 signal %s has family %q", sg.Name, sg.Family)
		}
	}
}

func TestTimingV2HTTPBeacon(t *testing.T) {
	s := newSynth(t)
	periodicHTTP(s, "10.5.0.11", "203.0.113.71", "status.example", 50, 2)
	res := s.analyze(Config{TimingV2: true})
	f := findBy(res, CatC2, "203.0.113.71")
	if f == nil || !hasSignal(f, "timing_dispersion") || hasSignal(f, "beacon_timing") {
		t.Fatalf("v2 finding lacks timing_dispersion (or still has v1 beacon_timing): %+v", f)
	}
	if f.Families["timing"] <= 0 {
		t.Errorf("family_scores missing timing: %v", f.Families)
	}
	ts := seriesBy(res, "http", "203.0.113.71")
	if ts == nil || ts.EventModel != ModelPerRequest || ts.V1Score == nil || ts.Timing == nil || ts.Timing.Rung != 30 {
		t.Fatalf("timing series: %+v", ts)
	}
	if ts.Timing.Spread == nil || *ts.Timing.Spread < 0.2 || *ts.Timing.Spread > 0.4 {
		t.Errorf("spread %v for shortening 30%%", ts.Timing.Spread)
	}
	if _, err := json.Marshal(res); err != nil {
		t.Fatalf("v2 result does not marshal: %v", err)
	}
}

// Spec Q1.2 gate: one beacon round-robined across three IPs behind one Host
// → one K1 series at the real period; per-IP series at ≈3× the period.
func TestTimingV2RoundRobinK1(t *testing.T) {
	s := newSynth(t)
	r := mrand.New(mrand.NewPCG(3, 3))
	servers := []string{"198.51.100.31", "198.51.100.32", "198.51.100.33"}
	conns := make([]*tcpSession, 3)
	for i, sv := range servers {
		conns[i] = s.tcp(s.now, "10.5.0.12", uint16(52000+i), sv, 80)
	}
	ts := s.now
	for i := 0; i < 90; i++ {
		ts = ts.Add(time.Duration(60 * (1 + 0.1*(2*r.Float64()-1)) * float64(time.Second)))
		c := conns[i%3]
		ts = c.Send(ts, true, httpReq("GET", "/sync", []string{"Host: cdn-updates.example", "User-Agent: agent"}, ""), 1400)
		ts = c.Send(ts.Add(30*time.Millisecond), false, httpResp("HTTP/1.1 204 No Content", nil, ""), 1400)
	}
	for _, c := range conns {
		c.Close(ts.Add(time.Second))
	}
	res := s.analyze(Config{TimingV2: true})

	k1 := seriesBy(res, "rollup", "K1|10.5.0.12|cdn-updates.example")
	if k1 == nil || k1.Timing == nil || k1.Timing.PeriodSec < 54 || k1.Timing.PeriodSec > 66 {
		t.Fatalf("K1 series: %+v", k1)
	}
	for _, sv := range servers {
		per := seriesBy(res, "http", sv)
		if per == nil || per.Timing == nil || per.Timing.PeriodSec < 160 || per.Timing.PeriodSec > 200 {
			t.Errorf("per-IP series %s: %+v", sv, per)
		}
		if f := findBy(res, CatC2, sv); f != nil {
			t.Errorf("v9c 2.1: per-IP finding %q should be rolled into the K1 finding", f.Title)
		}
	}
	f := findBy(res, CatC2, "cdn-updates.example")
	if f == nil || !hasSignal(f, "timing_dispersion_k1") {
		t.Fatalf("no K1 roll-up finding with K1 timing: %+v", f)
	}
	for _, sv := range servers {
		if !strings.Contains(strings.Join(f.Evidence, "\n"), sv) {
			t.Errorf("roll-up evidence does not list member %s", sv)
		}
	}
}

// SMB pipe legs are p2p: timing is refused, never scored.
func TestTimingV2RefusesP2P(t *testing.T) {
	s := newSynth(t)
	var payloads [][]byte
	for i := 0; i < 12; i++ {
		payloads = append(payloads, randB(64))
	}
	smbPipeSession(t, s, "10.5.0.13", "10.5.0.14", "p2p_leg", payloads...)
	res := s.analyze(Config{TimingV2: true})
	ts := seriesBy(res, "smb_pipe", "p2p_leg")
	if ts == nil || ts.Refused != "event_model:p2p" || ts.Timing != nil {
		t.Fatalf("pipe series: %+v", ts)
	}
	if f := findBy(res, CatPipe, "p2p_leg"); f != nil && (hasSignal(f, "timing_dispersion") || hasSignal(f, "beacon_timing")) {
		t.Errorf("p2p pipe scored on timing: %+v", f.Signals)
	}
}

// tinySession is one long-held TLS session carrying only ≤ 100 B
// exchanges at the given period with 10 % jitter (keep-alive-shaped).
func tinySession(t *testing.T, period float64, cfg Config) (*Finding, *Result) {
	s := newSynth(t)
	r := mrand.New(mrand.NewPCG(4, 4))
	ts := s.now
	c := s.tcp(ts, "10.5.0.15", 53000, "198.51.100.40", 443)
	ts = c.Send(ts.Add(5*time.Millisecond), true, clientHello("sync.example", []string{"h2"}), 1400)
	ts = c.Send(ts.Add(20*time.Millisecond), false, appData(400), 1400)
	for i := 0; i < 60; i++ {
		ts = ts.Add(time.Duration(period * (1 - 0.1*r.Float64()) * float64(time.Second)))
		ts = c.Send(ts, true, appData(35), 1400)
		ts = c.Send(ts.Add(20*time.Millisecond), false, appData(85), 1400)
	}
	c.Close(ts.Add(time.Second))
	res := s.analyze(cfg)
	return findBy(res, CatC2, "198.51.100.40"), res
}

func signalOf(f *Finding, name string) *stats.Signal {
	for i := range f.Signals {
		if f.Signals[i].Name == name {
			return &f.Signals[i]
		}
	}
	return nil
}

// Keep-alive-shaped session: event model persistent_heartbeat, the normal
// timing weight at every period, cadence match as annotation.
func TestTimingV2PersistentHeartbeat(t *testing.T) {
	f, res := tinySession(t, 30, Config{TimingV2: true})
	ts2 := seriesBy(res, "channel", "198.51.100.40")
	if ts2 == nil || ts2.EventModel != ModelHeartbeat {
		t.Fatalf("channel series: %+v", ts2)
	}
	if f == nil {
		t.Fatal("no finding")
	}
	sg := signalOf(f, "timing_dispersion")
	if sg == nil || !strings.Contains(sg.Detail, "transport keep-alive interval (30 s)") {
		t.Fatalf("heartbeat timing signal: %+v", f.Signals)
	}
	if hasSignal(f, "timing_persistent_heartbeat") {
		t.Error("separate low-weight heartbeat path still present")
	}
}

// v9 Phase 0.1 gate: no cadence cliff. ≤ 100 B bursts at 30 / 45 / 120 s
// score within 0.05 of the 45 s cell.
func TestTimingV2NoCadenceCliff(t *testing.T) {
	ref, _ := tinySession(t, 45, Config{TimingV2: true})
	if ref == nil {
		t.Fatal("no 45 s finding")
	}
	for _, p := range []float64{30, 120} {
		f, _ := tinySession(t, p, Config{TimingV2: true})
		if f == nil || f.Score < ref.Score-0.05 {
			t.Errorf("%.0f s: %v vs 45 s %.2f (cadence cliff)", p, f, ref.Score)
		}
	}
}

// beaconTLS is an HTTPS beacon with 10 % shortening jitter and
// application-sized, variable request/response records, either over one
// kept-alive TLS connection (WinINet/WinHTTP default) or a new connection
// per check-in. (From the v8a stress prototype.)
func beaconTLS(t *testing.T, reuse bool, period float64, cfg Config) (*Finding, *Result) {
	s := newSynth(t)
	r := mrand.New(mrand.NewPCG(7, 7))
	ts := s.now
	var c *tcpSession
	port := uint16(53000)
	open := func() {
		c = s.tcp(ts, "10.5.0.16", port, "198.51.100.41", 443)
		port++
		ts = c.Send(ts.Add(5*time.Millisecond), true, clientHello("cdn-update.example", []string{"http/1.1"}), 1400)
		ts = c.Send(ts.Add(20*time.Millisecond), false, appData(1400), 1400)
	}
	open()
	for i := 0; i < 60; i++ {
		ts = ts.Add(time.Duration(period * (1 - 0.1*r.Float64()) * float64(time.Second)))
		if !reuse {
			c.Close(ts.Add(-time.Second))
			open()
		}
		ts = c.Send(ts, true, appData(350+r.IntN(40)), 1400)
		ts = c.Send(ts.Add(40*time.Millisecond), false, appData(200+r.IntN(400)), 1400)
	}
	c.Close(ts.Add(time.Second))
	res := s.analyze(cfg)
	return findBy(res, CatC2, "198.51.100.41"), res
}

// v8a review finding 1: kept-alive HTTPS beacons at common sleeps were
// demoted to a 0.25-weight keep-alive note. v2 must score ≥ v1.
func TestTimingV2KeepaliveHTTPSBeacon(t *testing.T) {
	for _, period := range []float64{30, 60} {
		for _, reuse := range []bool{true, false} {
			f1, _ := beaconTLS(t, reuse, period, Config{})
			f2, res := beaconTLS(t, reuse, period, Config{TimingV2: true})
			if f1 == nil || f2 == nil {
				t.Fatalf("%.0fs reuse=%v: missing finding v1=%v v2=%v", period, reuse, f1 != nil, f2 != nil)
			}
			if f2.Score+1e-9 < f1.Score || hasSignal(f2, "timing_persistent_heartbeat") {
				t.Errorf("%.0fs reuse=%v: v2 %.2f < v1 %.2f or classed heartbeat: %+v", period, reuse, f2.Score, f1.Score, f2.Signals)
			}
			if ts := seriesBy(res, "channel", "198.51.100.41"); ts == nil || ts.EventModel != ModelPerRequest {
				t.Errorf("%.0fs reuse=%v: event model %+v", period, reuse, ts)
			}
		}
	}
}
