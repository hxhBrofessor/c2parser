package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"c2parser/internal/csconfig"
	"c2parser/internal/pcapio"
	"c2parser/internal/stats"
)

// analyzeEng writes the synth capture and runs it through an engine with an
// injected carver limiter (for deterministic overload tests), returning the
// result and the engine for telemetry inspection.
func (s *synth) analyzeEng(cfg Config, limit int) (*Result, *Engine) {
	s.t.Helper()
	dir := s.t.TempDir()
	p := filepath.Join(dir, "synth.pcap")
	if err := os.WriteFile(p, s.buf.Bytes(), 0o600); err != nil {
		s.t.Fatal(err)
	}
	r, err := pcapio.Open(p)
	if err != nil {
		s.t.Fatal(err)
	}
	defer r.Close()
	e := New(cfg)
	if limit > 0 {
		e.stagerLimiter = csconfig.NewLimiter(limit)
	}
	if err := e.Ingest(r); err != nil {
		s.t.Fatal(err)
	}
	res := e.Finish()
	return res, e
}

func respHead(server, ctype string, clen int) []byte {
	h := "HTTP/1.1 200 OK\r\nContent-Type: " + ctype + "\r\n"
	if clen >= 0 {
		h += "Content-Length: " + itoa(clen) + "\r\n"
	}
	return []byte(h + "\r\n")
}
func itoa(n int) string { return strconv.Itoa(n) }

// --- (b) admission branches -------------------------------------------------

func TestStagerAdmissionBranches(t *testing.T) {
	cases := []struct {
		name   string
		ctype  string
		body   []byte
		enc    string
		signal bool
	}{
		{"mz-octet", "application/octet-stream", plainStageFixture(), "", true},
		{"xor-octet", "application/octet-stream", xorStageFixture(), "", true},
		{"octet-large", "application/octet-stream", padTo(plainStageFixture(), 70<<10), "", true},
		{"octet-small-nonstage", "application/octet-stream", randBytesN(4096), "", false},
		{"text-plain", "text/plain", plainStageFixture(), "", false},
		{"json", "application/json", plainStageFixture(), "", false},
		{"gzip-encoding", "application/octet-stream", plainStageFixture(), "gzip", false},
		{"random-binary-unknown-type", "", randBytesN(4096), "", false},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newSynth(t)
			ts := s.now
			srv := "203.0.113." + itoa(60+i)
			c := s.tcp(ts, "10.7.0.9", uint16(51000+i), srv, 80)
			ts = c.Send(ts.Add(time.Second), true, httpReq("GET", "/a", []string{"Host: " + srv}, ""), 1400)
			hdrs := []string{"Content-Type: " + tc.ctype}
			if tc.ctype == "" {
				hdrs = nil
			}
			if tc.enc != "" {
				hdrs = append(hdrs, "Content-Encoding: "+tc.enc)
			}
			ts = c.Send(ts.Add(30*time.Millisecond), false, httpResp("HTTP/1.1 200 OK", hdrs, string(tc.body)), 1400)
			c.Close(ts.Add(time.Second))
			res := s.analyze(Config{})
			if got := hasStagerSignal(res, srv); got != tc.signal {
				t.Errorf("%s: signal=%v want %v", tc.name, got, tc.signal)
			}
		})
	}
}

// --- (e) sufficiency + scoring (OD-B44-3/10): never critical alone ----------

func TestStagerSufficiencyAndScoring(t *testing.T) {
	for _, v2 := range []bool{false, false} { // run v1 and v2
		_ = v2
	}
	run := func(t *testing.T, v2 bool) {
		// (1) isolated sufficient config -> signal, medium, never critical.
		s := newSynth(t)
		ts := s.now
		c := s.tcp(ts, "10.7.0.10", 52000, "203.0.113.70", 80)
		ts = c.Send(ts.Add(time.Second), true, httpReq("GET", "/a", []string{"Host: 203.0.113.70"}, ""), 1400)
		ts = c.Send(ts.Add(30*time.Millisecond), false, httpResp("HTTP/1.1 200 OK", []string{"Content-Type: application/octet-stream"}, string(plainStageFixture())), 1400)
		c.Close(ts.Add(time.Second))
		res := s.analyze(Config{TimingV2: v2})
		f := findBy(res, CatC2, "203.0.113.70")
		if f == nil || !hasSignal(f, stagerSignalName) {
			t.Fatalf("v2=%v: no cs_config finding", v2)
		}
		if stats.SeverityRank(f.Severity) >= stats.SeverityRank("critical") {
			t.Errorf("v2=%v: lone config reached critical (score %.2f) — STOP boundary", v2, f.Score)
		}
		if stats.Severity(f.Score) != f.Severity {
			t.Errorf("severity/score mismatch")
		}
		// (2) structurally valid but insufficient -> no signal.
		s2 := newSynth(t)
		ts = s2.now
		body := makePlainStage(0x1800, 0x2e, insufficientSettings(76))
		c2 := s2.tcp(ts, "10.7.0.11", 52010, "203.0.113.71", 80)
		ts = c2.Send(ts.Add(time.Second), true, httpReq("GET", "/a", []string{"Host: 203.0.113.71"}, ""), 1400)
		ts = c2.Send(ts.Add(30*time.Millisecond), false, httpResp("HTTP/1.1 200 OK", []string{"Content-Type: application/octet-stream"}, string(body)), 1400)
		c2.Close(ts.Add(time.Second))
		if hasStagerSignal(s2.analyze(Config{TimingV2: v2}), "203.0.113.71") {
			t.Errorf("v2=%v: insufficient config emitted a signal", v2)
		}
	}
	t.Run("v1", func(t *testing.T) { run(t, false) })
	t.Run("v2", func(t *testing.T) { run(t, true) })
}

// --- (d) feed cap -----------------------------------------------------------

func TestStagerFeedCap(t *testing.T) {
	s := newSynth(t)
	ts := s.now
	big := padTo(plainStageFixture(), (4<<20)+(1<<20)) // > 4 MiB
	c := s.tcp(ts, "10.7.0.12", 52020, "203.0.113.72", 80)
	ts = c.Send(ts.Add(time.Second), true, httpReq("GET", "/a", []string{"Host: 203.0.113.72"}, ""), 1400)
	ts = c.Send(ts.Add(30*time.Millisecond), false, httpResp("HTTP/1.1 200 OK", []string{"Content-Type: application/octet-stream"}, string(big)), 1400)
	c.Close(ts.Add(time.Second))
	res, e := s.analyzeEng(Config{}, 0)
	if hasStagerSignal(res, "203.0.113.72") {
		t.Error("feed-capped response still emitted a signal")
	}
	if e.stager == nil || e.stager.feedCapReached == 0 {
		t.Error("feed_cap_reached not counted")
	}
}

// --- (c) lifecycle: 33 simultaneous eligible responses ----------------------

func TestStagerConcurrency33(t *testing.T) {
	s := newSynth(t)
	ts := s.now
	// 33 flows: each sends req + response head (large CL) + a partial MZ body
	// fragment, so each tap admits and holds a slot without completing.
	var sess []*tcpSession
	for i := 0; i < 33; i++ {
		srv := "198.51.100." + itoa(i+1)
		c := s.tcp(ts, "10.8.0.9", uint16(53000+i), srv, 80)
		sess = append(sess, c)
		ts = ts.Add(5 * time.Millisecond)
		c.Send(ts, true, httpReq("GET", "/a", []string{"Host: " + srv}, ""), 1400)
	}
	// interleave the partial responses (admission happens here)
	frag := append([]byte{'M', 'Z'}, randBytesN(200)...)
	for i, c := range sess {
		ts = ts.Add(5 * time.Millisecond)
		head := respHead("", "application/octet-stream", 1<<20) // CL huge -> stays open
		c.Send(ts, false, append(head, frag...), 1400)
		_ = i
	}
	for _, c := range sess {
		c.Close(ts.Add(time.Second))
	}
	_, e := s.analyzeEng(Config{}, 32)
	admitted := e.stager.admitMZ + e.stager.admitOctet + e.stager.admitXor
	if admitted != 32 {
		t.Errorf("admitted=%d want 32", admitted)
	}
	if e.stager.resourceLimit < 1 {
		t.Errorf("resource_limit=%d want >=1", e.stager.resourceLimit)
	}
	if n := stagerProbesNow(); n != 0 {
		t.Errorf("probe slots leaked: %d", n)
	}
}

// repeated admit+release cycles on a size-1 limiter must never leak a slot.
func TestStagerNoSlotLeak(t *testing.T) {
	lim := csconfig.NewLimiter(1)
	for i := 0; i < 40; i++ {
		e := New(Config{})
		e.stagerLimiter = lim
		tp := e.newStagerTap(&tcpConn{}, &httpMsg{hdr: map[string]string{"content-type": "application/octet-stream"}})
		tp.feed(plainStageFixture())
		tp.finalize(true)
		tp.finalize(true) // idempotent
	}
	// after all cycles the one slot is free: a fresh carver can acquire it.
	c := csconfig.New(csconfig.Options{Limiter: lim})
	if c.Reason() == csconfig.ReasonResourceLimit {
		t.Fatal("slot leaked across admit/release cycles")
	}
	c.Close()
}

// --- VA-0 BLIND -------------------------------------------------------------

func TestStagerVA0Blind(t *testing.T) {
	s := newSynth(t)
	ts := s.now
	c := s.tcp(ts, "10.7.0.20", 52100, "203.0.113.80", 80)
	ts = c.Send(ts.Add(time.Second), true, httpReq("GET", "/a", []string{"Host: 203.0.113.80"}, ""), 1400)
	ts = c.Send(ts.Add(30*time.Millisecond), false, httpResp("HTTP/1.1 200 OK", []string{"Content-Type: application/octet-stream"}, string(plainStageFixture())), 1400)
	c.Close(ts.Add(time.Second))
	br := s.analyzeBlind(Config{})
	// FULL: the config finding exists and may name Cobalt Strike.
	if !hasStagerSignal(&Result{Findings: br.Full}, "203.0.113.80") {
		t.Fatal("FULL: no cs_config signal")
	}
	// BLIND: config-only finding disappears; no cs_config signal; no framework name.
	for _, f := range br.Blind {
		for _, sg := range f.Signals {
			if sg.Name == stagerSignalName {
				t.Error("BLIND still carries cs_config:beacon_config")
			}
		}
	}
	blob, _ := json.Marshal(br.Blind)
	if strings.Contains(strings.ToLower(string(blob)), "cobalt strike") {
		t.Error("BLIND output names Cobalt Strike")
	}
	// ledger records the suppression.
	ok := false
	for _, en := range br.Ledger.Entries {
		for _, sgp := range en.Suppressed {
			if sgp.Name == stagerSignalName {
				ok = true
			}
		}
	}
	if !ok {
		t.Error("ledger did not record cs_config:beacon_config suppression")
	}
}

func stagerProbesNow() int32 { return loadProbes() }

func padTo(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	return append(b, make([]byte, n-len(b))...)
}

func randBytesN(n int) []byte { return randB(n) }

// --- (f) evidence: order, 128-byte cap, escaping, no raw/watermark ----------

func TestStagerEvidence(t *testing.T) {
	// a config with SLEEPTIME, JITTER, a control-char SUBMITURI, an oversized
	// USERAGENT, a WATERMARK (index 37, must NOT appear), plus PUBKEY/maxIndex.
	longUA := strings.Repeat("A", 300)
	settings := []synthSetting{
		{3, csconfig.TypeInt, []byte{0, 0, 0x27, 0x10}},
		{5, csconfig.TypeShort, []byte{0, 30}},
		{7, csconfig.TypePtr, append([]byte{0x30, 0x81, 0x20}, synthOID...)},
		{10, csconfig.TypePtr, []byte("/a\x01\x02b")},
		{9, csconfig.TypePtr, []byte(longUA)},
		{37, csconfig.TypePtr, []byte("WATERMARK-SECRET-1234")},
		{76, csconfig.TypeInt, []byte{0, 0, 0, 76}},
	}
	body := makePlainStage(0x1800, 0x2e, settings)
	s := newSynth(t)
	ts := s.now
	c := s.tcp(ts, "10.7.0.30", 52200, "203.0.113.90", 80)
	ts = c.Send(ts.Add(time.Second), true, httpReq("GET", "/a", []string{"Host: 203.0.113.90"}, ""), 1400)
	ts = c.Send(ts.Add(30*time.Millisecond), false, httpResp("HTTP/1.1 200 OK", []string{"Content-Type: application/octet-stream"}, string(body)), 1400)
	c.Close(ts.Add(time.Second))
	f := findBy(s.analyze(Config{}), CatC2, "203.0.113.90")
	if f == nil {
		t.Fatal("no finding")
	}
	var ev []string
	for _, e := range f.Evidence {
		if strings.HasPrefix(e, "Sleep:") || strings.HasPrefix(e, "Jitter:") || strings.HasPrefix(e, "SubmitURI:") ||
			strings.HasPrefix(e, "UserAgent:") || strings.HasPrefix(e, "HostHeader:") || strings.HasPrefix(e, "Pipename:") ||
			strings.HasPrefix(e, "Version:") || strings.HasPrefix(e, "Xorencoded:") {
			ev = append(ev, e)
		}
	}
	// fixed order: Sleep, Jitter, SubmitURI, UserAgent, [Host], [Pipe], Version, Xorencoded
	wantPrefixOrder := []string{"Sleep:", "Jitter:", "SubmitURI:", "UserAgent:", "Version:", "Xorencoded:"}
	if len(ev) != len(wantPrefixOrder) {
		t.Fatalf("evidence lines = %v", ev)
	}
	for i, p := range wantPrefixOrder {
		if !strings.HasPrefix(ev[i], p) {
			t.Errorf("evidence[%d]=%q want prefix %q", i, ev[i], p)
		}
	}
	blob := strings.Join(f.Evidence, "\n")
	if strings.Contains(blob, "WATERMARK") || strings.Contains(blob, "\x01") {
		t.Error("evidence contains watermark or raw control bytes")
	}
	if !strings.Contains(blob, "\\x01") {
		t.Error("control char not escaped")
	}
	for _, e := range ev {
		if strings.HasPrefix(e, "UserAgent:") && len(e) > len("UserAgent: ")+stagerEvidenceCap {
			t.Errorf("UserAgent not capped at 128 bytes: len=%d", len(e))
		}
	}
	// repeat-run JSON identity for the finding signals/evidence.
	f2 := findBy(s.analyze(Config{}), CatC2, "203.0.113.90")
	a, _ := json.Marshal(f.Evidence)
	b, _ := json.Marshal(f2.Evidence)
	if string(a) != string(b) {
		t.Error("evidence not deterministic across runs")
	}
}

// --- G-4.7 additions register: exactly 4 rows on the ws4-synthetic lane -----

func TestG47AdditionsRegister(t *testing.T) {
	type row struct{ Lane, Fixture, Engine, Added string }
	var reg []row
	fixtures := []struct {
		name string
		body []byte
	}{{"csconfig-plain", plainStageFixture()}, {"csconfig-xorencoded", xorStageFixture()}}
	for _, fx := range fixtures {
		for _, v2 := range []bool{false, true} {
			eng := "v1"
			if v2 {
				eng = "v2"
			}
			count := func(on bool) int {
				streamStager = on
				defer func() { streamStager = true }()
				s := newSynth(t)
				ts := s.now
				c := s.tcp(ts, "10.9.9.9", 55000, "203.0.113.99", 80)
				ts = c.Send(ts.Add(time.Second), true, httpReq("GET", "/s", []string{"Host: 203.0.113.99"}, ""), 1400)
				ts = c.Send(ts.Add(30*time.Millisecond), false, httpResp("HTTP/1.1 200 OK", []string{"Content-Type: application/octet-stream"}, string(fx.body)), 1400)
				c.Close(ts.Add(time.Second))
				n := 0
				for _, f := range s.analyze(Config{TimingV2: v2}).Findings {
					for _, sg := range f.Signals {
						if sg.Name == stagerSignalName {
							n++
						}
					}
				}
				return n
			}
			base := count(false)
			branch := count(true)
			if base != 0 {
				t.Errorf("%s/%s: base (tap off) already has %d cs_config signals", fx.name, eng, base)
			}
			if branch-base != 1 {
				t.Errorf("%s/%s: additions = %d, want exactly 1", fx.name, eng, branch-base)
			}
			reg = append(reg, row{"ws4-synthetic", fx.name, eng, "one cs_config:beacon_config"})
		}
	}
	if len(reg) != 4 {
		t.Fatalf("register rows = %d, want 4", len(reg))
	}
	if path := os.Getenv("B44_REGISTER"); path != "" {
		b, _ := json.MarshalIndent(reg, "", " ")
		os.WriteFile(path, b, 0o644)
	}
}
