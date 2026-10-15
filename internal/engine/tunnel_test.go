package engine

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	sy "c2parser/internal/synth"
)

// connectSession writes a CONNECT tunnel through proxy carrying either a
// TLS session (ClientHello, then records) or opaque bytes, n check-ins.
func connectSession(s *synth, tlsInside bool, n int) {
	ts := s.now
	c := s.tcp(ts, "10.5.0.40", 55000, "10.0.0.8", 3128)
	ts = c.Send(ts.Add(5*time.Millisecond), true, httpReq("CONNECT", "beacon.example:443", []string{"Host: beacon.example:443"}, ""), 1400)
	ts = c.Send(ts.Add(5*time.Millisecond), false, []byte("HTTP/1.1 200 Connection established\r\n\r\n"), 1400)
	if tlsInside {
		ts = c.Send(ts.Add(5*time.Millisecond), true, clientHello("beacon.example", []string{"http/1.1"}), 1400)
		ts = c.Send(ts.Add(20*time.Millisecond), false, appData(1400), 1400)
	}
	for i := 0; i < n; i++ {
		ts = ts.Add(time.Duration(60*(1-0.1*float64(i%7)/7)) * time.Second)
		if tlsInside {
			ts = c.Send(ts, true, appData(300+i%40), 1400)
			ts = c.Send(ts.Add(40*time.Millisecond), false, appData(200+i%300), 1400)
		} else {
			ts = c.Send(ts, true, randB(300+i%40), 1400)
			ts = c.Send(ts.Add(40*time.Millisecond), false, randB(200+i%300), 1400)
		}
	}
	c.Close(ts.Add(time.Second))
}

// v9c 2.3: TLS inside an HTTP CONNECT tunnel is parsed; a K1 series keyed
// by the CONNECT target is scored; non-TLS tunnels behave as in v9b.
func TestConnectTLS(t *testing.T) {
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		s := newSynth(t)
		connectSession(s, true, 60)
		res := s.analyze(cfg)
		f := findBy(res, CatC2, "beacon.example:443 via proxy")
		if f == nil || f.Score < 0.4 || !strings.Contains(strings.Join(f.Evidence, " "), "inner TLS SNI: beacon.example") {
			t.Fatalf("v2=%v: no tunnel finding with the inner SNI: %+v", cfg.TimingV2, f)
		}
		if cfg.TimingV2 {
			if ts := seriesBy(res, "connect_tunnel", "K1|10.5.0.40|beacon.example"); ts == nil || ts.Timing == nil {
				t.Errorf("no K1 tunnel series: %+v", ts)
			}
		}
	}
	// non-TLS: identical findings with and without the feature
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		s := newSynth(t)
		connectSession(s, false, 60)
		connectTLS = false
		before := s.analyze(cfg)
		connectTLS = true
		after := s.analyze(cfg)
		if a, b := findingTitles(before), findingTitles(after); a != b {
			t.Errorf("v2=%v: non-TLS tunnel changed findings\n %s\n %s", cfg.TimingV2, a, b)
		}
	}
	// mutation: without the hand-off there is no tunnel finding
	connectTLS = false
	s := newSynth(t)
	connectSession(s, true, 60)
	if f := findBy(s.analyze(Config{}), CatC2, "via proxy"); f != nil {
		t.Errorf("hand-off disabled but %q found", f.Title)
	}
	connectTLS = true
}

func findingTitles(r *Result) string {
	var b strings.Builder
	for _, f := range r.Findings {
		b.WriteString(f.Title)
		b.WriteString("|")
	}
	return b.String()
}

// FuzzConnectTunnel: arbitrary bytes after a successful CONNECT never
// panic the HTTP → TLS hand-off.
func FuzzConnectTunnel(f *testing.F) {
	f.Add(sy.ClientHello("x.example", []string{"h2"}), []byte{0x16, 3, 3, 0, 4, 2, 0, 0, 0}, 3)
	f.Add([]byte("SSH-2.0-OpenSSH_9.6\r\n"), []byte("SSH-2.0-x\r\n"), 0)
	f.Fuzz(func(t *testing.T, a, b []byte, split int) {
		e := New(Config{})
		c := &tcpConn{client: netip.MustParseAddrPort("10.0.0.1:5000"), server: netip.MustParseAddrPort("10.0.0.8:3128"), ch: &channel{}}
		cli, srv := newHTTPHalf(e, c, true), newHTTPHalf(e, c, false)
		now := time.Now()
		cli.feed([]byte("CONNECT t.example:443 HTTP/1.1\r\nHost: t.example:443\r\n\r\n"), now, 1)
		srv.feed([]byte("HTTP/1.1 200 OK\r\n\r\n"), now, 2)
		if split < 0 {
			split = -split
		}
		sa, sb := split%(len(a)+1), split%(len(b)+1)
		cli.feed(a[:sa], now, 3)
		srv.feed(b[:sb], now, 4)
		cli.feed(a[sa:], now, 5)
		srv.feed(b[sb:], now, 6)
		e.connBurst(c, now, int64(len(a)))
		e.score()
	})
}
