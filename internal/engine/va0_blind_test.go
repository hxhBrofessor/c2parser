package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"c2parser/internal/sigma"
	"c2parser/internal/stats"
)

// VA-0 slice 1 tests (test-first). Framework-blind policy, registry
// completeness (fail-closed), per-class suppression, finding existence,
// correlation rederivation, Sigma non-folding, VA-4 output scan, R0-3 severity
// boundaries, FULL identity.

func (s *synth) analyzeBlind(cfg Config) *BlindResult {
	s.t.Helper()
	dir := s.t.TempDir()
	p := filepath.Join(dir, "synth.pcap")
	if err := os.WriteFile(p, s.buf.Bytes(), 0o600); err != nil {
		s.t.Fatal(err)
	}
	br, err := AnalyzeFileBlind(p, cfg)
	if err != nil {
		s.t.Fatal(err)
	}
	return br
}

func havocHTTP(s *synth) {
	ts := s.now
	ua := "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
	c := s.tcp(ts, "10.9.3.32", 52100, "203.0.113.10", 80)
	for i := 0; i < 20; i++ {
		ts = ts.Add(5 * time.Second)
		ts = c.Send(ts, true, httpReq("POST", "/", []string{"Host: 203.0.113.10", "User-Agent: " + ua, "Content-Type: */*"}, string(randB(64))), 1400)
		ts = c.Send(ts.Add(30*time.Millisecond), false, httpResp("HTTP/1.1 200 OK", []string{"Content-Type: application/octet-stream"}, ""), 1400)
	}
	c.Close(ts.Add(time.Second))
}

func havocRule(t *testing.T) []*sigma.Rule {
	t.Helper()
	rules, rep := sigma.Load("../../rules/sigma")
	if len(rules) == 0 {
		t.Fatalf("no built-in rules: %+v", rep)
	}
	return rules
}

// (a) R2 registry completeness + fail-closed mutation.
func TestVA0RegistryCompleteness(t *testing.T) {
	p := newEvidencePolicy(FrameworkBlindMode)
	known := []string{
		"beacon_timing", "encoded_payload_in_query", "encoded_payload_in_resp", "encoded_volume",
		"hdr:invalid_request_content_type", "hdr:ua_browser_without_browser_headers", "hdr:ua_missing",
		"ldap_acl_sweep", "ldap_bulk_enum", "length_residue", "long_connection", "long_labels",
		"long_names", "name_cardinality_ratio", "pipe_volume", "pivot_frame_header",
		"positional_randomness", "random_payloads", "random_pipe_data", "random_ws_payloads",
		"recon_from_c2_host", "rpc:IWbemServices:ExecMethod", "timing_dispersion", "timing_dispersion_k1",
		"timing_interactive_on_periodic", "tunnel_record_types", "unique_subdomains", "unrecognised_pipe",
		"uri_shape:fixed-uri", "uri_shape:word-dot-ext", "websocket_push_mode", "wireguard_shape_on_dns_port",
		"sig:mythic-agent-message", "sig:havoc-demon-header", "c2_framing_in_pipe", "mythic_message_in_pipe",
		"c2_default_pipe_name", "hdr:server_c2_default", "sigma:e1f2bf20", "pivot_from_c2_host",
		"same_channel_as_c2", "uuid_pipe_name", "default_profile:cobaltstrike",
	}
	for _, n := range known {
		if p.classify(n) == classUnknown {
			t.Errorf("registry cannot classify known signal %q", n)
		}
	}
	for _, bad := range []string{"totally_made_up_signal", "sigma:deadbeef", "uri_shape:martian", "default_profile:acme", "hdr:made_up", "sig:made_up"} {
		if p.classify(bad) != classUnknown {
			t.Errorf("fake/unregistered name %q must be UNKNOWN (fail-closed), got %v", bad, p.classify(bad))
		}
	}
}

// (b) per-class suppression.
func TestVA0PerClassSuppression(t *testing.T) {
	p := newEvidencePolicy(FrameworkBlindMode)
	if !p.suppresses("c2_framing_in_pipe") {
		t.Error("framework_specific c2_framing_in_pipe must be suppressed")
	}
	if !p.suppresses("sigma:e1f2bf20") {
		t.Error("sigma_attribution sigma:e1f2bf20 must be suppressed")
	}
	if p.suppresses("beacon_timing") || p.suppresses("uri_shape:fixed-uri") {
		t.Error("generic signals must be retained")
	}
	if p.suppresses("recon_from_c2_host") {
		t.Error("derived_correlation recon_from_c2_host must be rederived, not suppressed")
	}
}

// (c) existence + score monotonicity: BLIND score never exceeds FULL for the
// same finding key, and the ledger exists.
func TestVA0FindingExistenceAndScore(t *testing.T) {
	s := newSynth(t)
	havocHTTP(s)
	br := s.analyzeBlind(Config{Sigma: havocRule(t)})
	if br.Ledger == nil {
		t.Fatal("no ledger")
	}
	full := map[string]float64{}
	for _, f := range br.Full {
		full[f.Category+"|"+f.Server] = f.Score
	}
	for _, f := range br.Blind {
		if fs, ok := full[f.Category+"|"+f.Server]; ok && f.Score > fs+1e-9 {
			t.Errorf("BLIND score %.3f exceeds FULL %.3f for %s|%s", f.Score, fs, f.Category, f.Server)
		}
	}
}

// (d) correlation rederived: recon_from_c2_host appears in BLIND only with a
// surviving blind C2 host.
func TestVA0CorrelationRederived(t *testing.T) {
	s := newSynth(t)
	havocHTTP(s)
	br := s.analyzeBlind(Config{})
	for _, f := range br.Blind {
		for _, sg := range f.Signals {
			if sg.Name == "recon_from_c2_host" {
				ok := false
				for _, c2 := range br.Blind {
					if c2.Category == CatC2 && c2.Client == f.Client && c2.Score >= 0.6 {
						ok = true
					}
				}
				if !ok {
					t.Errorf("recon_from_c2_host in BLIND without a surviving blind C2 host for %s", f.Client)
				}
			}
		}
	}
}

// (e) Sigma folded in FULL, never in BLIND.
func TestVA0SigmaNotFoldedInBlind(t *testing.T) {
	s := newSynth(t)
	havocHTTP(s)
	br := s.analyzeBlind(Config{Sigma: havocRule(t)})
	has := func(fs []Finding) bool {
		for _, f := range fs {
			for _, sg := range f.Signals {
				if strings.HasPrefix(sg.Name, "sigma:e1f2bf20") {
					return true
				}
			}
		}
		return false
	}
	if !has(br.Full) {
		t.Error("FULL must fold sigma:e1f2bf20")
	}
	if has(br.Blind) {
		t.Error("BLIND must never fold sigma:e1f2bf20")
	}
}

// (f) VA-4: BLIND output names no framework.
func TestVA0BlindOutputNoFrameworkNames(t *testing.T) {
	p := newEvidencePolicy(FrameworkBlindMode)
	names := p.frameworkNames()
	if len(names) == 0 {
		t.Fatal("empty framework-name list")
	}
	s := newSynth(t)
	havocHTTP(s)
	br := s.analyzeBlind(Config{Sigma: havocRule(t)})
	blob, _ := json.Marshal(br.Blind)
	low := strings.ToLower(string(blob))
	for _, n := range names {
		if strings.Contains(low, strings.ToLower(n)) {
			t.Errorf("BLIND output names framework %q", n)
		}
	}
	// V0-1: the placeholder token must not appear either (it reveals that a
	// framework was recognized).
	if strings.Contains(string(blob), "[framework]") {
		t.Error("BLIND output contains the [framework] placeholder token")
	}
}

// (g) R0-3 severity boundaries: the harness severity uses production
// Severity(round2(score)).
func TestVA0SeverityBoundaries(t *testing.T) {
	for _, raw := range []float64{0.394, 0.395, 0.400} {
		want := stats.Severity(round2(raw))
		if got := vaSeverity(raw); got != want {
			t.Errorf("vaSeverity(%.3f)=%q want production Severity(round2)=%q", raw, got, want)
		}
	}
}
