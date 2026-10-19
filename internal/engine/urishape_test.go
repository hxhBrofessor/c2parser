package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"c2parser/internal/stats"
	sy "c2parser/internal/synth"
)

// stagerPath returns the first 4-char alnum path with checksum8 == want.
func stagerPath(want int, skip int) string {
	const al = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	for _, a := range al {
		for _, b := range al {
			for _, c := range al {
				for _, d := range al {
					p := "/" + string([]rune{a, b, c, d})
					if s, ok := checksum8(p); ok && s == want {
						if skip == 0 {
							return p
						}
						skip--
					}
				}
			}
		}
	}
	return ""
}

func TestURIShapeOf(t *testing.T) {
	x86, x64 := stagerPath(92, 0), stagerPath(93, 0)
	for path, want := range map[string]string{
		x86: "checksum8-x86", x64: "checksum8-x64",
		"/updates.rss": "word-dot-ext", "/pixel.gif": "word-dot-ext", "/submit.php": "word-dot-ext",
		"/api/v4/users": "", "/index": "", "/a.php": "", "/Updates.RSS": "", "/updates.json": "",
		"/abcde": "", x86 + "/x": "", "/api/v1/update": "",
	} {
		if got := uriShapeOf(path); got != want {
			t.Errorf("uriShapeOf(%q) = %q, want %q", path, got, want)
		}
	}
	// x86 decision: the 4-char rule stays for x86 — a longer path with
	// byte sum ≡ 92 is not a stager URI.
	long := "/" + strings.Repeat("A", 4) + "x"
	for c := byte('A'); c <= 'z'; c++ {
		p := long[:len(long)-1] + string(c)
		s := 0
		for i := 1; i < len(p); i++ {
			s += int(p[i])
		}
		if s%256 == 92 {
			if uriShapeOf(p) != "" {
				t.Errorf("5-char path %q with sum 92 classified %q", p, uriShapeOf(p))
			}
			break
		}
	}
}

// stagerChannel: one GET of path answered by respBytes of octet-stream,
// then a few unrelated requests.
func stagerChannel(t *testing.T, path string, respBytes int, cfg Config) *Result {
	t.Helper()
	s := newSynth(t)
	r := seeded(81, 82)
	ts := s.now
	sess := s.tcp(ts, "10.1.1.30", 53000, "203.0.113.88", 80)
	ts = sess.Send(ts, true, sy.HTTPReq("GET", path, []string{"Host: 203.0.113.88", "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)"}, ""), 1400)
	ts = sess.Send(ts.Add(20*time.Millisecond), false, sy.HTTPResp("HTTP/1.1 200 OK", []string{"Content-Type: application/octet-stream"}, string(rbytes(r, respBytes))), 1400)
	sess.Close(ts.Add(time.Second))
	return s.analyze(cfg)
}

func uriSignal(res *Result, server, name string) *stats.Signal {
	for i := range res.Findings {
		f := &res.Findings[i]
		if !strings.Contains(f.Title, server) {
			continue
		}
		for j := range f.Signals {
			if f.Signals[j].Name == name {
				return &f.Signals[j]
			}
		}
	}
	return nil
}

func TestURIShapeStagerFixtures(t *testing.T) {
	for _, tc := range []struct {
		want int
		fam  string
	}{{92, "checksum8-x86"}, {93, "checksum8-x64"}} {
		path := stagerPath(tc.want, 3)
		for _, cfg := range []Config{{}, {TimingV2: true}} {
			// staged download: score 1
			res := stagerChannel(t, path, 300<<10, cfg)
			sg := uriSignal(res, "203.0.113.88", "uri_shape:"+tc.fam)
			if sg == nil || sg.Score != 1 || sg.Weight != uriShapeWeight {
				t.Errorf("%s staged v2=%v: %+v", tc.fam, cfg.TimingV2, sg)
			}
			if other := map[string]string{"checksum8-x86": "uri_shape:checksum8-x64", "checksum8-x64": "uri_shape:checksum8-x86"}[tc.fam]; uriSignal(res, "203.0.113.88", other) != nil {
				t.Errorf("%s: wrong family also fired", tc.fam)
			}
			// bare hit (small response): score 0.5, stays below low alone
			res = stagerChannel(t, path, 2000, cfg)
			sg = uriSignal(res, "203.0.113.88", "uri_shape:"+tc.fam)
			if sg == nil || sg.Score != 0.5 {
				t.Errorf("%s bare v2=%v: %+v", tc.fam, cfg.TimingV2, sg)
			} else if sg.Contribution() >= 0.2 {
				t.Errorf("%s bare hit contributes %.2f (≥ low on its own)", tc.fam, sg.Contribution())
			}
		}
		// the Cobalt Strike default-profile feature is unchanged, byte for byte
		ch := &httpChannel{}
		e := &Engine{}
		e.matchFrameworkDefaults(ch, &httpMsg{req: true, method: "GET", uri: path, hdr: map[string]string{}, frame: 7})
		want := fmt.Sprintf("stager URI %s (checksum8 = %d)", path, tc.want)
		if st := ch.fw["Cobalt Strike"]; st == nil || st.feats[want] != 0.35 || len(st.feats) != 1 {
			t.Errorf("CS stager feature changed: %+v", st)
		}
	}
}

// benignPoll: n GETs from one client at irregular intervals (no beacon).
func benignPoll(t *testing.T, n int, uri func(i int) string, cfg Config) *Result {
	t.Helper()
	s := newSynth(t)
	r := seeded(91, 92)
	ts := s.now
	sess := s.tcp(ts, "10.1.1.40", 54000, "203.0.113.99", 80)
	for i := 0; i < n; i++ {
		ts = ts.Add(time.Duration(1+r.IntN(600)) * time.Second)
		ts = sess.Send(ts, true, sy.HTTPReq("GET", uri(i), []string{"Host: app.example", "User-Agent: app/1.0", "Accept: application/json"}, ""), 1400)
		ts = sess.Send(ts.Add(30*time.Millisecond), false, sy.HTTPResp("HTTP/1.1 200 OK", []string{"Content-Type: application/json"}, `{"ok":true}`), 1400)
	}
	sess.Close(ts.Add(time.Second))
	return s.analyze(cfg)
}

func TestURIShapeBenignNegatives(t *testing.T) {
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		res := benignPoll(t, 15, func(int) string { return "/api/v4/users" }, cfg)
		for _, f := range res.Findings {
			for _, s := range f.Signals {
				if strings.HasPrefix(s.Name, "uri_shape:") {
					t.Errorf("v2=%v /api/v4/users fired %s", cfg.TimingV2, s.Name)
				}
			}
		}
		// a browser-like client fetching many different static files
		// is not polling a word-dot-ext URI
		files := []string{"/style.css", "/app.js", "/logo.png", "/index.html", "/favicon.ico", "/vendor.js"}
		res = benignPoll(t, 18, func(i int) string { return files[i%len(files)] }, cfg)
		if sg := uriSignal(res, "203.0.113.99", "uri_shape:word-dot-ext"); sg != nil {
			t.Errorf("v2=%v static-file browsing fired word-dot-ext: %+v", cfg.TimingV2, sg)
		}
	}
	// a polled /updates.rss is the shape (irregular timing: no cap involved)
	res := benignPoll(t, 10, func(int) string { return "/updates.rss" }, Config{})
	if sg := uriSignal(res, "203.0.113.99", "uri_shape:word-dot-ext"); sg == nil || sg.Score != 1 {
		t.Errorf("polled /updates.rss: %+v", sg)
	}
}

// Cap-safety mutation matrix for the two fleet gates. Each protection —
// fixed-uri in the timing family, and the timing+URI-shape guard — keeps
// the fleet-capped series ≤ TimingOnlyCap on its own; removing the
// protections that apply lifts it, so the gate tests the rule.
func TestURIShapeCapMutations(t *testing.T) {
	type gate struct {
		scenario, server, client string
		v2Only                   bool // fixed-uri is a v2 signal
	}
	fixed := gate{"gate-fleet3-http-fixed-uri", "198.51.100.111", "10.50.1.11", true}
	word := gate{"gate-fleet3-http-word-dot-ext", "198.51.100.112", "10.50.2.11", false}
	defer func(a, b bool) { stats.FixedURITimingFamily, uriShapeCapTiming = a, b }(stats.FixedURITimingFamily, uriShapeCapTiming)
	for _, tc := range []struct {
		name        string
		g           gate
		family, cap bool
		wantCapped  bool
	}{
		{"fixed-uri: both protections", fixed, true, true, true},
		{"fixed-uri: timing family only", fixed, true, false, true},
		{"fixed-uri: guard only", fixed, false, true, true},
		{"fixed-uri: neither (mutation)", fixed, false, false, false},
		{"word-dot-ext: guard", word, true, true, true},
		{"word-dot-ext: no guard (mutation)", word, true, false, false},
	} {
		stats.FixedURITimingFamily, uriShapeCapTiming = tc.family, tc.cap
		for _, cfg := range []Config{{}, {TimingV2: true}} {
			if tc.g.v2Only && !cfg.TimingV2 {
				continue
			}
			s := scenarioScore(t, tc.g.scenario, tc.g.server, tc.g.client, cfg)
			if capped := s <= TimingOnlyCap; capped != tc.wantCapped {
				t.Errorf("%s v2=%v: score %.2f, want capped=%v", tc.name, cfg.TimingV2, s, tc.wantCapped)
			}
		}
	}
}
