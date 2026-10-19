package stats

import "testing"

// v10a.1 D2: signals with no named family are reported under "unmapped";
// the reported families still multiply out to the score.
func TestReportedFamilyScoresUnmapped(t *testing.T) {
	sigs := []Signal{
		{Name: "beacon_timing", Weight: 0.6, Score: 1},
		{Name: "rpc:IWbemServices:ExecMethod", Weight: 0.7, Score: 1},
		{Name: "unrecognised_pipe", Weight: 0.3, Score: 1},
		{Name: "ldap_spn_enum", Weight: 0.45, Score: 1},
	}
	AssignFamilies(sigs)
	rep := ReportedFamilyScores(sigs)
	if _, ok := rep["rpc:IWbemServices:ExecMethod"]; ok || rep[UnmappedFamily] == 0 || rep["timing"] == 0 || rep["recon"] == 0 {
		t.Fatalf("reported families %v", rep)
	}
	p := 1.0
	for _, v := range rep {
		p *= 1 - v
	}
	if d := (1 - p) - NoisyORFamilies(sigs); d > 1e-12 || d < -1e-12 {
		t.Errorf("reported families give %.6f, score %.6f", 1-p, NoisyORFamilies(sigs))
	}
	for name, want := range map[string]bool{"beacon_timing": false, "ldap_acl_sweep": false, "recon_from_c2_host": false, "rpc:x": true, "pipe_volume": true, "websocket_push_mode": true} {
		if Unmapped(name) != want {
			t.Errorf("Unmapped(%s) = %v", name, !want)
		}
	}
}

// v11a: structural payload signals map to payload_shape (they were unmapped,
// each its own family); URI shapes map to http_client_quirks, except
// fixed-uri which rides the timing family so the timing-only cap holds.
func TestV11aFamilyMappings(t *testing.T) {
	shape := []string{"encoded_payload_in_query", "encoded_payload_in_resp", "sig:mythic-agent-message",
		"mythic_message_in_pipe", "pivot_frame_header", "length_residue"}
	for _, n := range shape {
		if f := FamilyOf(n); f != "payload_shape" {
			t.Errorf("FamilyOf(%s) = %q, want payload_shape", n, f)
		}
	}
	if Unmapped("encoded_payload_in_path") {
		t.Error("encoded_payload_in_path still unmapped")
	}
	for _, n := range []string{"uri_shape:checksum8-x86", "uri_shape:checksum8-x64", "uri_shape:word-dot-ext"} {
		if f := FamilyOf(n); f != "http_client_quirks" {
			t.Errorf("FamilyOf(%s) = %q, want http_client_quirks", n, f)
		}
	}
	if f := FamilyOf("uri_shape:fixed-uri"); f != "timing" {
		t.Errorf("FamilyOf(uri_shape:fixed-uri) = %q, want timing", f)
	}
	defer func(v bool) { FixedURITimingFamily = v }(FixedURITimingFamily)
	FixedURITimingFamily = false
	if f := FamilyOf("uri_shape:fixed-uri"); f != "http_client_quirks" {
		t.Errorf("mutation: FamilyOf(uri_shape:fixed-uri) = %q, want http_client_quirks", f)
	}
	// folding two payload_shape signals into one family can only reduce the
	// combined lift vs unmapped (each its own family).
	sigs := []Signal{
		{Name: "encoded_payload_in_query", Weight: 0.55, Score: 1},
		{Name: "sig:mythic-agent-message", Weight: 0.97, Score: 1},
	}
	AssignFamilies(sigs)
	fam := NoisyORFamilies(sigs)
	plain := NoisyOR(sigs)
	if fam > plain+1e-12 {
		t.Errorf("family fold %.4f > plain noisy-OR %.4f", fam, plain)
	}
}
