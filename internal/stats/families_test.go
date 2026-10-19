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
