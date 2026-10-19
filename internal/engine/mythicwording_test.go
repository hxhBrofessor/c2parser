package engine

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	sy "c2parser/internal/synth"
)

func TestMythicHeuristicDetailsDescribeObservedStructure(t *testing.T) {
	tests := []struct {
		name, got, want string
	}{
		{"uuid-pipe", mythicUUIDPipeDetail(), "pipe name is a bare UUID (Mythic-style profile heuristic, unconfirmed)"},
		{"pipe", mythicPipeDetail(3), "3 Base64 runs with an ASCII-UUID prefix (Mythic-style heuristic, unconfirmed) in pipe data"},
		{"http", mythicHTTPDetail("header:x-session", 12, 12, "requests"), "Decoded token with an ASCII-UUID prefix (Mythic-style heuristic, unconfirmed) in header:x-session (12 of 12 requests)"},
		{"http-body", httpSignatureDetail("mythic-agent-message", 12, 24), "UUID-prefix framing heuristic (Mythic-style; attribution unconfirmed) in 12 of 24 HTTP bodies"},
		{"other-http-signature", httpSignatureDetail("other-signature", 2, 24), "other-signature framing in 2 of 24 HTTP bodies"},
		{"websocket", mythicWebSocketDetail(4), "Mythic-style UUID-prefix heuristic (unconfirmed) matched in 4 WebSocket messages"},
		{"raw-tcp", mythicRawTCPDetail(2), "Mythic-style UUID-prefix heuristic (unconfirmed) matched 2 times in the TCP stream"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("detail = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestPlaintextUUIDJSONHeuristicChangesOnlyDetail(t *testing.T) {
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		res := carrierChannelCfg(t, 12, func(i int) carrierMsg {
			plain := fmt.Sprintf(`550e8400-e29b-41d4-a716-4466554400%02d{"user":"alice","page":%d,"lang":"en-US"}`, i, i)
			return carrierMsg{reqHdrs: []string{"X-Session: " + base64.StdEncoding.EncodeToString([]byte(plain))}, body: "ok"}
		}, cfg)
		f, detail := carrierSignal(res, "sig:mythic-agent-message")
		if f == nil {
			t.Fatal("missing UUID-prefix heuristic finding")
		}
		if f.Category != CatC2 || f.Title != "HTTP C2 10.1.1.20 → 203.0.113.77:80 (Host: carrier.example)" || f.Client != "10.1.1.20" || f.Server != "203.0.113.77" {
			t.Fatalf("finding identity changed: %+v", f)
		}
		if fmt.Sprint(f.ServerNames) != "[carrier.example]" {
			t.Fatalf("server-name identity changed: %v", f.ServerNames)
		}
		if f.Score != 0.97 || f.Severity != "critical" {
			t.Fatalf("score/severity changed: %.2f %s", f.Score, f.Severity)
		}
		wantSignals := map[string][2]float64{"sig:mythic-agent-message": {0.97, 1}}
		if cfg.TimingV2 {
			if f.Families["payload_shape"] != 0.97 {
				t.Fatalf("v2 family score changed: %+v", f.Families)
			}
		} else {
			wantSignals["beacon_timing"] = [2]float64{0.75, 0}
		}
		seen := make(map[string]bool)
		for _, s := range f.Signals {
			want, ok := wantSignals[s.Name]
			if !ok || s.Weight != want[0] || s.Score != want[1] {
				t.Fatalf("signal set or score/weight changed: %+v", f.Signals)
			}
			seen[s.Name] = true
		}
		if len(seen) != len(wantSignals) || !seen["sig:mythic-agent-message"] {
			t.Fatalf("signal set changed: %+v", f.Signals)
		}
		want := "Decoded token with an ASCII-UUID prefix (Mythic-style heuristic, unconfirmed) in header:x-session (12 of 12 requests)"
		if detail != want {
			t.Fatalf("detail = %q, want %q", detail, want)
		}
		wantEvidence := []string{"12 requests / 12 responses; 0 B up, 24 B down", "User-Agent: test/1.0", "methods: GET×12; URIs: /×12"}
		if fmt.Sprint(f.Evidence) != fmt.Sprint(wantEvidence) {
			t.Fatalf("evidence changed: %+v", f.Evidence)
		}
		wantFrames := []int64{4}
		if !cfg.TimingV2 {
			wantFrames = []int64{4, 1}
		}
		if fmt.Sprint(f.Frames) != fmt.Sprint(wantFrames) || f.First != "2024-03-25T12:00:41Z" || f.Last != "2024-03-25T12:05:23Z" {
			t.Fatalf("frames or time identity changed: %+v", f)
		}
	}
}

func TestR3HTTPCarrierWordingFixtures(t *testing.T) {
	for _, tc := range []struct {
		name, location, value string
	}{
		{"header-base64", "header:x-session", base64.StdEncoding.EncodeToString(uuidJSON(1))},
		{"query-base64", "query:x", base64.RawURLEncoding.EncodeToString(uuidJSON(1))},
		{"header-hex", "header:x-session", hex.EncodeToString(uuidJSON(1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, cfg := range []Config{{}, {TimingV2: true}} {
				res := carrierChannelCfg(t, 12, func(i int) carrierMsg {
					value := tc.value
					if i != 1 {
						switch tc.name {
						case "header-base64":
							value = base64.StdEncoding.EncodeToString(uuidJSON(i))
						case "query-base64":
							value = base64.RawURLEncoding.EncodeToString(uuidJSON(i))
						case "header-hex":
							value = hex.EncodeToString(uuidJSON(i))
						}
					}
					m := carrierMsg{}
					if tc.name == "query-base64" {
						m.uri = "/?x=" + value
					} else {
						m.reqHdrs = []string{"X-Session: " + value}
					}
					return m
				}, cfg)
				f, detail := carrierSignal(res, "sig:mythic-agent-message")
				if f == nil {
					t.Fatal("missing UUID-prefix carrier signal")
				}
				want := fmt.Sprintf("Decoded token with an ASCII-UUID prefix (Mythic-style heuristic, unconfirmed) in %s (12 of 12 requests)", tc.location)
				if detail != want {
					t.Fatalf("TimingV2=%v detail=%q, want %q", cfg.TimingV2, detail, want)
				}
				assertR3FindingStable(t, f, 0.97)
				assertR3CarrierSignals(t, f, cfg)
			}
		})
	}
}

func TestR3HTTPBodyWordingFixtures(t *testing.T) {
	for _, direction := range []string{"request", "response"} {
		t.Run(direction, func(t *testing.T) {
			for _, cfg := range []Config{{}, {TimingV2: true}} {
				res := mythicHTTPBodyFixture(t, direction == "request", cfg)
				f, detail := carrierSignal(res, "sig:mythic-agent-message")
				if f == nil {
					t.Fatal("missing UUID-prefix body signal")
				}
				want := "UUID-prefix framing heuristic (Mythic-style; attribution unconfirmed) in 12 of 24 HTTP bodies"
				if detail != want {
					t.Fatalf("TimingV2=%v detail=%q, want %q", cfg.TimingV2, detail, want)
				}
				assertR3FindingStable(t, f, 0.99)
				assertR3BodySignals(t, f, cfg)
				wantEvidence := []string{"12 requests / 12 responses; 1.5 KB up, 24 B down", "User-Agent: test/1.0"}
				if direction == "request" {
					wantEvidence[0] = "12 requests / 12 responses; 1.5 KB up, 24 B down"
					wantEvidence = append(wantEvidence, "methods: POST×12; URIs: /api×12")
				} else {
					wantEvidence[0] = "12 requests / 12 responses; 0 B up, 1.5 KB down"
					wantEvidence = append(wantEvidence, "methods: GET×12; URIs: /×12")
				}
				if fmt.Sprint(f.Evidence) != fmt.Sprint(wantEvidence) {
					t.Fatalf("evidence changed: %v", f.Evidence)
				}
				wantFrames := []int64{4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26}
				if direction == "response" {
					wantFrames = []int64{4, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25}
				}
				if fmt.Sprint(f.Frames) != fmt.Sprint(wantFrames) || f.First != "2024-03-25T12:00:07Z" || f.Last != "2024-03-25T12:01:45Z" {
					t.Fatalf("frames/times changed: frames=%v first=%s last=%s", f.Frames, f.First, f.Last)
				}
			}
		})
	}
}

func uuidJSON(i int) []byte {
	return []byte(fmt.Sprintf(`550e8400-e29b-41d4-a716-4466554400%02d{"user":"alice","page":%d,"lang":"en-US","pad":"xxxxxxxx"}`, i, i))
}

func mythicHTTPBodyFixture(t *testing.T, requestBody bool, cfg Config) *Result {
	t.Helper()
	s := newSynth(t)
	ts := s.now
	sess := s.tcp(ts, "10.1.1.20", 52000, "203.0.113.77", 80)
	for i := 0; i < 12; i++ {
		ts = ts.Add(time.Duration(7+i%5) * time.Second)
		body := base64.StdEncoding.EncodeToString(uuidJSON(i))
		method, uri, reqBody, respBody := "GET", "/", "", "ok"
		if requestBody {
			method, uri, reqBody = "POST", "/api", body
		} else {
			respBody = body
		}
		ts = sess.Send(ts, true, sy.HTTPReq(method, uri, []string{"Host: carrier.example", "User-Agent: test/1.0", "Content-Type: text/plain"}, reqBody), 1400)
		ts = sess.Send(ts.Add(30*time.Millisecond), false, sy.HTTPResp("HTTP/1.1 200 OK", []string{"Content-Type: text/plain"}, respBody), 1400)
	}
	sess.Close(ts.Add(time.Second))
	return s.analyze(cfg)
}

func assertR3FindingStable(t *testing.T, f *Finding, wantScore float64) {
	t.Helper()
	if f.Category != CatC2 || f.Title != "HTTP C2 10.1.1.20 → 203.0.113.77:80 (Host: carrier.example)" || f.Client != "10.1.1.20" || f.Server != "203.0.113.77" || fmt.Sprint(f.ServerNames) != "[carrier.example]" {
		t.Fatalf("finding identity changed: %+v", f)
	}
	if f.Score != wantScore || f.Severity != "critical" {
		t.Fatalf("score/severity changed: %.2f %s", f.Score, f.Severity)
	}
	found := false
	for _, s := range f.Signals {
		if s.Name == "sig:mythic-agent-message" {
			found = true
			if s.Weight != 0.97 || s.Score != 1 {
				t.Fatalf("signal score/weight changed: %+v", s)
			}
		}
	}
	if !found || len(f.Evidence) == 0 || len(f.Frames) == 0 || f.First == "" || f.Last == "" {
		t.Fatalf("signal/evidence/time fields missing: %+v", f)
	}
}

func assertR3CarrierSignals(t *testing.T, f *Finding, cfg Config) {
	t.Helper()
	want := map[string][2]float64{"sig:mythic-agent-message": {0.97, 1}}
	if !cfg.TimingV2 {
		want["beacon_timing"] = [2]float64{0.75, 0}
	}
	seen := map[string]bool{}
	for _, s := range f.Signals {
		v, ok := want[s.Name]
		if !ok || s.Weight != v[0] || s.Score != v[1] {
			t.Fatalf("carrier signal set/values changed: %+v", f.Signals)
		}
		seen[s.Name] = true
	}
	if len(seen) != len(want) {
		t.Fatalf("carrier signal set changed: %+v", f.Signals)
	}
	if cfg.TimingV2 && f.Families["payload_shape"] != 0.97 {
		t.Fatalf("v2 payload family changed: %v", f.Families)
	}
}

func assertR3BodySignals(t *testing.T, f *Finding, cfg Config) {
	t.Helper()
	want := map[string][2]float64{"sig:mythic-agent-message": {0.97, 1}}
	if !cfg.TimingV2 {
		want["beacon_timing"] = [2]float64{0.75, 1}
	} else {
		want["timing_dispersion"] = [2]float64{0.75, 0.82}
		want["uri_shape:fixed-uri"] = [2]float64{0.3, 1}
		if f.Families["payload_shape"] != 0.97 || f.Families["timing"] != 0.65 {
			t.Fatalf("v2 family scores changed: %v", f.Families)
		}
	}
	seen := map[string]bool{}
	for _, s := range f.Signals {
		v, ok := want[s.Name]
		if !ok || s.Weight != v[0] || s.Score != v[1] {
			t.Fatalf("body signal set/values changed: %+v", f.Signals)
		}
		seen[s.Name] = true
	}
	if len(seen) != len(want) {
		t.Fatalf("body signal set changed: %+v", f.Signals)
	}
}
