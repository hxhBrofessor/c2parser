package engine

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"c2parser/data"
)

// C2 certificate intelligence. Team servers generate their TLS certificates
// in code that operators rarely touch, so certificates outlast most HTTP
// signatures. Two layers:
//
//   - knownC2Cert: exact defaults (serial, SHA-256, distinguished name) of
//     specific frameworks — very high specificity.
//   - certAnomalies: framework-agnostic oddities that real CAs and real
//     products don't produce (empty issuer DN, Microsoft-branded self-signed
//     certs, generator-shaped validity spans).
//
// Only TLS ≤ 1.2 exposes the server certificate on the wire; TLS 1.3
// encrypts it.

type certHit struct {
	name   string
	weight float64
	detail string
}

type certificateIdentityLookup struct {
	sha256 map[string]string
	serial map[string]string
	dn     []data.Item
}

var certificateIdentityOnce sync.Once
var certificateIdentityTable certificateIdentityLookup
var certificateIdentityErr error

func buildCertificateIdentityLookup(p data.Profiles) (certificateIdentityLookup, error) {
	items, err := registeredFrameworkCertItems(p)
	if err != nil {
		return certificateIdentityLookup{}, err
	}
	out := certificateIdentityLookup{sha256: map[string]string{}, serial: map[string]string{}}
	for _, framework := range []string{"cobaltstrike", "bruteratel"} {
		for _, item := range items[framework+"/cert"] {
			switch item.Kind {
			case "cert_der_sha256_exact":
				if _, exists := out.sha256[item.Value]; exists {
					return certificateIdentityLookup{}, fmt.Errorf("CERT_PROFILE_DUPLICATE_SHA256")
				}
				out.sha256[item.Value] = item.Feature
			case "cert_serial_decimal_exact":
				if _, exists := out.serial[item.Value]; exists {
					return certificateIdentityLookup{}, fmt.Errorf("CERT_PROFILE_DUPLICATE_SERIAL")
				}
				out.serial[item.Value] = item.Feature
			case "cert_dn_contains_folded":
				out.dn = append(out.dn, item)
			}
		}
	}
	if len(out.sha256) != 3 || len(out.serial) != 2 || len(out.dn) != 1 {
		return certificateIdentityLookup{}, fmt.Errorf("CERT_PROFILE_ITEM_SET_MISMATCH")
	}
	return out, nil
}

func loadCertificateIdentityLookup(p data.Profiles) (certificateIdentityLookup, error) {
	certificateIdentityOnce.Do(func() { certificateIdentityTable, certificateIdentityErr = buildCertificateIdentityLookup(p) })
	return certificateIdentityTable, certificateIdentityErr
}

func ensureCertificateIdentityLookup() (certificateIdentityLookup, error) {
	certificateIdentityOnce.Do(func() {
		p, err := data.Load()
		if err != nil {
			certificateIdentityErr = err
			return
		}
		certificateIdentityTable, certificateIdentityErr = buildCertificateIdentityLookup(p)
	})
	return certificateIdentityTable, certificateIdentityErr
}

func firstOr(v []string) string {
	if len(v) > 0 {
		return v[0]
	}
	return ""
}

// knownC2Cert reports a framework-default certificate.
func knownC2Cert(ci *certInfo) (string, bool) {
	if ci == nil {
		return "", false
	}
	lookup, err := ensureCertificateIdentityLookup()
	if err != nil {
		return "", false
	}
	if why, ok := lookup.sha256[strings.ToLower(ci.SHA256)]; ok {
		return why, true
	}
	if why, ok := lookup.serial[ci.Serial]; ok {
		return why, true
	}
	dn := strings.ToLower(ci.Subject + " " + ci.Issuer)
	for _, item := range lookup.dn {
		for _, value := range item.Values {
			if strings.Contains(dn, value) {
				return item.Feature, true
			}
		}
	}
	c := ci.cert
	if c == nil {
		return "", false
	}
	cn, org, ou := c.Subject.CommonName, firstOr(c.Subject.Organization), firstOr(c.Subject.OrganizationalUnit)
	switch {
	case cn == "P18055077" || org == "Pajfds" && ou == "Jethpro":
		// Hard-coded in PoshC2's Config.py; changing it needs a code edit.
		return "PoshC2 default certificate (CN=P18055077, O=Pajfds)", true
	case cn == "Covenant" && ci.SelfSigned:
		return "Covenant default admin certificate (self-signed CN=Covenant)", true
	case org == "Microsoft" && ou == "Security" && cn == "localhost":
		return "Brute Ratel C4 certificate DN (O=Microsoft, OU=Security, CN=localhost)", true
	case c.Issuer.CommonName == "operators" && cn == "multiplayer":
		return "Sliver multiplayer operator certificate (issuer CN=operators)", true
	}
	return "", false
}

// generatorSpans are validity periods C2 cert generators hard-code: Sliver
// 730/1095 days, Merlin 2 years, PoshC2/Covenant 3650 days (AddDate-style
// year arithmetic adds a leap day or two).
var generatorSpans = map[int]string{730: "2 y", 731: "2 y", 1095: "3 y", 1096: "3 y", 3650: "10 y", 3651: "10 y", 3652: "10 y", 3653: "10 y"}

// certAnomalies returns framework-agnostic certificate oddities.
func certAnomalies(ci *certInfo) []certHit {
	if ci == nil || ci.cert == nil {
		return nil
	}
	c := ci.cert
	var out []certHit
	emptyIssuer := len(c.Issuer.Names) == 0
	emptySubject := len(c.Subject.Names) == 0
	switch {
	case emptyIssuer && emptySubject:
		out = append(out, certHit{"cert_empty_dn", 0.7,
			"certificate has an empty subject and issuer DN (Merlin's in-memory certificate; no CA or product issues these)"})
	case emptyIssuer:
		out = append(out, certHit{"cert_empty_issuer", 0.6,
			"certificate issuer DN is empty (Sliver's CA has no RDNs; real CAs always name themselves)"})
	}
	if ci.SelfSigned {
		org := strings.ToLower(strings.Join(c.Subject.Organization, " "))
		if strings.Contains(org, "microsoft") {
			out = append(out, certHit{"cert_selfsigned_microsoft", 0.7,
				fmt.Sprintf("self-signed certificate claims O=%s (Microsoft never self-signs; BRc4-style impersonation)", strings.Join(c.Subject.Organization, ","))})
		}
	}
	if ci.SelfSigned || emptyIssuer {
		span := c.NotAfter.Sub(c.NotBefore)
		if span > 0 && span%(24*time.Hour) == 0 {
			days := int(span / (24 * time.Hour))
			if label, ok := generatorSpans[days]; ok {
				w := 0.3
				if days >= 3650 {
					w = 0.2 // openssl -days 3650 is also a common admin habit
				}
				out = append(out, certHit{"cert_generator_validity", w,
					fmt.Sprintf("validity is exactly %d days (%s) on a self-issued certificate — a C2 generator default (Sliver 730/1095, Merlin 2 y, PoshC2/Covenant 3650)", days, label)})
			}
		}
	}
	return out
}
