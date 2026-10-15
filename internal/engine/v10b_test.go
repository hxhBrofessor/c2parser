package engine

import (
	"testing"

	sy "c2parser/internal/synth"
)

// v10b (from the v10a.1 lab review): the Windows Group Policy client reads
// each applicable GPO's security descriptor with SD_FLAGS under
// CN=Policies,CN=System on every refresh. From a host with no C2 finding
// that is not recon. Mutation: without the Policies guard it is a medium
// standalone finding (0.45, as the lab review measured). A real ACL dump
// from the domain root still fires.
func TestReconGPOSecurityReads(t *testing.T) {
	gpo := sy.GPOSecurityQuery(reconBase, "gPCUserExtensionNames")
	run := func(qs ...ldapQuery) []*Finding {
		s := newSynth(t)
		ldapSessionFx(s, s.now, "10.30.0.40", 50800, "10.30.0.10", krbRRC(false, 12), qs...)
		return reconFindings(s.analyze(Config{}))
	}
	gq := ldapQuery{gpo.Base, gpo.Scope, gpo.Filter, gpo.Attrs, gpo.Entries, gpo.Pages, gpo.Ctls}
	if r := run(gq); len(r) != 0 {
		t.Errorf("gpsvc SD reads scored: %+v", r[0])
	}
	gpoSDGuard = false
	r := run(gq)
	gpoSDGuard = true
	if len(r) != 1 || r[0].Score != 0.45 || !hasSignal(r[0], "ldap_acl_collection") {
		t.Errorf("mutation: want the 0.45 ldap_acl_collection finding back, got %+v", r)
	}
	root := ldapQuery{reconBase, 2, sy.FPresent("objectClass"), []string{"nTSecurityDescriptor"}, 40, 0, [][]byte{sy.SDFlagsControl()}}
	if r := run(gq, root); len(r) != 1 || !hasSignal(r[0], "ldap_acl_collection") {
		t.Errorf("domain-root ACL dump no longer fires: %+v", r)
	}
}

func fleetWithPipe(t *testing.T) *sy.Scenario {
	sc, err := sy.LoadScenario("../../corpus/scenarios/gate-fleet3-https-60s.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pipe, err := sy.LoadScenario("../../corpus/scenarios/shape-smb-pipe-framed.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// a steadier, longer fleet schedule: raw score above correlate's 0.65
	// bar, still capped at 0.39 as a fleet-wide destination
	sc.Streams[0].Timing.Jitter, sc.Streams[0].Timing.Events = 0.02, 200
	st := pipe.Streams[0]
	st.Topology.Clients = []string{"10.50.0.11"} // a fleet member opens a framed pipe
	sc.Streams = append(sc.Streams, st)
	return sc
}

// v10b (v10a.1 follow-up): a fleet-capped beacon host lends no
// pivot_from_c2_host to its pipe. The decision reads the capped score.
// Mutation: with the raw pre-cap score the pipe gets the pivot signal.
func TestCorrelateIgnoresCappedC2(t *testing.T) {
	sc := fleetWithPipe(t)
	pipeHas := func(cfg Config) (bool, *Finding) {
		res := analyzeScenario(t, sc, cfg)
		for i := range res.Findings {
			f := &res.Findings[i]
			if f.Category == CatC2 && f.Client == "10.50.0.11" && f.Score > TimingOnlyCap {
				t.Errorf("fleet member lost its cap: %.2f", f.Score)
			}
		}
		for i := range res.Findings {
			if f := &res.Findings[i]; f.Category == CatPipe && f.Client == "10.50.0.11" {
				return hasSignal(f, "pivot_from_c2_host"), f
			}
		}
		t.Fatalf("no pipe finding: %+v", res.Findings)
		return false, nil
	}
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		if got, f := pipeHas(cfg); got {
			t.Errorf("v2=%v: pipe took pivot_from_c2_host from a capped fleet beacon: %+v", cfg.TimingV2, f.Signals)
		}
	}
	correlateCapAware = false
	defer func() { correlateCapAware = true }()
	if got, _ := pipeHas(Config{}); !got {
		t.Error("mutation: raw-score correlate gives no pivot either — the fixture can't see the rule")
	}
}
