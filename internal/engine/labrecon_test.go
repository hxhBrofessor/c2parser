package engine

import (
	"strings"
	"testing"
)

// v10a 2.2 lab gates. The enum captures (Havoc HTTP C2 host running AD
// enumeration) attach recon evidence to the Havoc finding and make no
// standalone recon finding; the smb2 captures (workstation and data
// server, routine domain traffic plus the gainz pivot) make no recon at
// all. Skips without C2PARSER_TESTDATA.
func TestCaptureReconEnum(t *testing.T) {
	for _, name := range []string{"http_c2_enum", "part2"} {
		t.Run(name, func(t *testing.T) {
			res := analyzeCapture(t, name, Config{})
			c2 := findBy(res, CatC2, "100.113.27.34")
			if c2 == nil {
				t.Fatal("no Havoc finding")
			}
			if !hasSignal(c2, "recon_from_c2_host") || !hasEvidence(c2, "AD recon:") {
				t.Errorf("no recon evidence on the Havoc finding: %+v %v", c2.Signals, c2.Evidence)
			}
			for _, e := range c2.Evidence {
				t.Log(e)
			}
			// v10a.1 (lab review): the Havoc host reads each account's
			// security descriptor one object at a time over Kerberos-signed
			// LDAP (RRC = 12) — needs the rotation fix and ldap_acl_sweep
			if name == "http_c2_enum" {
				if s := signalOf(c2, "recon_from_c2_host"); s == nil || !strings.Contains(s.Detail, "ldap_acl_sweep") || !strings.Contains(s.Detail, "ldap_uac_delegation") {
					t.Errorf("http_c2_enum recon lacks ldap_acl_sweep / ldap_uac_delegation: %+v", s)
				}
			}
			if r := reconFindings(res); len(r) != 0 {
				t.Errorf("standalone recon on an enum capture: %+v", r)
			}
		})
	}
}

func TestCaptureReconSMB2None(t *testing.T) {
	for _, name := range []string{"smb2-wks", "smb2-data"} {
		t.Run(name, func(t *testing.T) {
			res := analyzeCapture(t, name, Config{})
			for _, f := range res.Findings {
				if f.Category == CatRecon {
					t.Errorf("recon finding on %s: %.2f %s %+v", name, f.Score, f.Title, f.Signals)
				}
				for _, s := range f.Signals {
					if s.Name == "recon_from_c2_host" {
						t.Errorf("recon_from_c2_host on %s: %s", name, s.Detail)
					}
				}
			}
		})
	}
}
