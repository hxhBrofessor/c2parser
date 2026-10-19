package engine

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"c2parser/internal/stats"
)

// Optional, sanitized evidence export for the local F07 investigation. Normal
// tests write no artifact. The original matched-control assertions stay intact.
func TestDNSCorrelationEvidence(t *testing.T) {
	type signalRow struct {
		Name                        string `json:"name"`
		Weight, Score, Contribution float64
		Family                      string
		Unmapped                    bool
	}
	type record struct {
		Sessions                                         int
		V2                                               bool
		Domain                                           string
		RawScore, FinalScore                             float64
		Severity, Cap                                    string
		Queries, Logical, Retries, Unique, MaxLabel      int
		AvgLength, Cardinality, TTLZero, PositionalScore float64
		Prefix                                           string
		Signals                                          []signalRow
		Ablation                                         map[string]float64
	}
	var records []record
	for _, sessions := range []int{1, 3} {
		for _, cfg := range []Config{{}, {TimingV2: true}} {
			res := sourceDNSCapture(t, sourceDNSQueries(t, "mixed", sessions), cfg)
			for _, zone := range []string{"safe.example", "wire.example", "hash.example"} {
				f := findBy(res, CatDNS, zone)
				if f == nil {
					t.Fatal("missing correlation finding", zone)
				}
				d := studyDomain(t, res, zone)
				combine := func(s []stats.Signal) float64 {
					if cfg.TimingV2 {
						return stats.NoisyORFamilies(s)
					}
					return stats.NoisyOR(s)
				}
				rec := record{Sessions: sessions, V2: cfg.TimingV2, Domain: zone, RawScore: combine(f.Signals), FinalScore: f.Score, Severity: f.Severity, Cap: capEvidence(f), Queries: d.Queries, Logical: d.Logical, Retries: d.Retries, Unique: d.UniqueSubs, MaxLabel: d.MaxLabel, AvgLength: d.AvgSubLen, Cardinality: d.Cardinality, TTLZero: d.TTL0Share, PositionalScore: d.Positional.Score, Prefix: d.Positional.Prefix, Ablation: map[string]float64{}}
				for _, s := range f.Signals {
					rec.Signals = append(rec.Signals, signalRow{s.Name, s.Weight, s.Score, s.Contribution(), stats.FamilyOf(s.Name), stats.Unmapped(s.Name)})
				}
				for _, mode := range []string{"without-long-names", "without-long-labels", "without-both-lengths", "without-positional", "without-timing"} {
					var ss []stats.Signal
					for _, s := range f.Signals {
						if (mode == "without-long-names" || mode == "without-both-lengths") && s.Name == "long_names" {
							continue
						}
						if (mode == "without-long-labels" || mode == "without-both-lengths") && s.Name == "long_labels" {
							continue
						}
						if mode == "without-positional" && s.Name == "positional_randomness" {
							continue
						}
						if mode == "without-timing" && stats.FamilyOf(s.Name) == "timing" {
							continue
						}
						ss = append(ss, s)
					}
					rec.Ablation[mode] = combine(ss)
				}
				t.Logf("CORRELATION sessions=%d v2=%v domain=%s raw=%.6f final=%.2f %s cap=%s names=%d logical=%d retries=%d ratio=%.2f ttl0=%.2f prefix=%q positional=%.2f ablation=%v", sessions, cfg.TimingV2, zone, rec.RawScore, f.Score, f.Severity, rec.Cap, d.UniqueSubs, d.Logical, d.Retries, d.Cardinality, d.TTL0Share, d.Positional.Prefix, d.Positional.Score, rec.Ablation)
				records = append(records, rec)
			}
		}
	}
	if path := os.Getenv("C2PARSER_F07_EVIDENCE"); path != "" {
		b, err := json.MarshalIndent(records, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, append(b, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDNSQueryShapeGuardBoundaries(t *testing.T) {
	shape := []stats.Signal{{Name: "long_names", Score: 1, Weight: .4}, {Name: "long_labels", Score: 1, Weight: .3},
		{Name: "unique_subdomains", Score: .14, Weight: .55}, {Name: "positional_randomness", Score: .3, Weight: .45},
		{Name: "tunnel_record_types", Score: .4, Weight: .35}, {Name: "encoded_volume", Score: .09, Weight: .6},
		{Name: "beacon_timing", Score: .18, Weight: .5}}
	if !dnsQueryShapeOnly(shape) {
		t.Fatal("correlated shape constellation not recognized")
	}
	// Every separately observed behavior and specific/unknown indicator must
	// prevent capping; a permissive default protects future independent signals.
	for _, name := range []string{"name_cardinality_ratio", "ttl_zero_answers", "data_in_address_answers", "resolved_never_contacted", "cs_dns_defaults", "ioc:domain", "sigma:test", "future_dns_indicator"} {
		for _, contribution := range []float64{negligible, 1} {
			sigs := append(append([]stats.Signal{}, shape...), stats.Signal{Name: name, Weight: 1, Score: contribution})
			if dnsQueryShapeOnly(sigs) {
				t.Errorf("independent %s contribution %.2f was capped", name, contribution)
			}
		}
	}
	if dnsQueryShapeOnly(shape[1:]) {
		t.Fatal("guard must require both contributing length views")
	}
	if dnsQueryShapeOnly([]stats.Signal{{Name: "long_names", Score: 1, Weight: .4}, {Name: "long_labels", Score: .01, Weight: .3}}) {
		t.Fatal("negligible second length view must not trigger guard")
	}
	if !dnsQueryShapeOnly(append(shape, stats.Signal{Name: "timing_dispersion", Score: .3, Weight: .5})) {
		t.Fatal("timing family should remain inside shape-only evidence")
	}
}

func TestDNSCorrelationGuardMutation(t *testing.T) {
	saved := dnsShapeCap
	defer func() { dnsShapeCap = saved }()
	if !saved {
		t.Fatal("DNS correlation guard must start enabled")
	}
	for _, sessions := range []int{1, 3} {
		for _, cfg := range []Config{{}, {TimingV2: true}} {
			qs := sourceDNSQueries(t, "mixed", sessions)
			fixed := sourceDNSCapture(t, qs, cfg)
			benign := findBy(fixed, CatDNS, "safe.example")
			suspect := findBy(fixed, CatDNS, "wire.example")
			if benign == nil || benign.Score >= .4 || benign.Severity != "low" || !strings.Contains(capEvidence(benign), "correlated DNS query-name") {
				t.Fatal("matched negative not protected", benign)
			}
			if suspect == nil || suspect.Score < .65 || strings.Contains(capEvidence(suspect), "correlated DNS query-name") {
				t.Fatal("independent suspicious evidence capped")
			}
			func() {
				defer func() { dnsShapeCap = saved }()
				dnsShapeCap = false
				mutated := sourceDNSCapture(t, qs, cfg)
				mb := findBy(mutated, CatDNS, "safe.example")
				ms := findBy(mutated, CatDNS, "wire.example")
				if mb == nil || mb.Score < .4 {
					t.Fatal("guard removal did not reproduce false positive")
				}
				if !reflect.DeepEqual(benign.Signals, mb.Signals) {
					t.Fatal("guard altered signal weights/scores instead of controlling correlation")
				}
				if ms == nil || ms.Score != suspect.Score || !reflect.DeepEqual(ms.Signals, suspect.Signals) {
					t.Fatal("suspicious independent evidence changed")
				}
				t.Logf("GUARD_MUTATION sessions=%d v2=%v cached=%.2f/%s -> off=%.2f/%s suspicious=%.2f/%s unchanged", sessions, cfg.TimingV2, benign.Score, benign.Severity, mb.Score, mb.Severity, suspect.Score, suspect.Severity)
			}()
			if dnsShapeCap != saved {
				t.Fatal("guard restoration failed")
			}
			// Actual channel-level IOC evidence must lift the very same cached case.
			iocCfg := cfg
			iocCfg.IOCs = []IOC{{Kind: "domain", Value: "safe.example", Label: "F07 explicit test indicator"}}
			indicated := findBy(sourceDNSCapture(t, qs, iocCfg), CatDNS, "safe.example")
			if indicated == nil || indicated.Score <= .84 || !hasSignal(indicated, "ioc:domain") || strings.Contains(capEvidence(indicated), "correlated DNS query-name") {
				t.Fatal("independent IOC did not escape correlation guard")
			}
			t.Logf("INDEPENDENT_IOC sessions=%d v2=%v cached+IOC=%.2f/%s", sessions, cfg.TimingV2, indicated.Score, indicated.Severity)
		}
	}
}
