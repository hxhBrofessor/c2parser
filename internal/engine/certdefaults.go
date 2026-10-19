package engine

import (
	"fmt"
	"strings"
	"time"
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

// knownCertSHA256 maps lower-case SHA-256 fingerprints of the DER encoding.
var knownCertSHA256 = map[string]string{
	"87f2085c32b6a2cc709b365f55873e207a9caa10bffecf2fd16d3cf9d94d390c": "Cobalt Strike default team-server certificate",
	"56a06a233bd30f693de25ef12cc19e8b2c92d3eb97dd969a2578df084c376478": "Cobalt Strike second widely-seen default certificate",
	"d597d6572c5616573170275d0b5d5e3ab0c06d4a9104bbdbe952c4bcb52118c9": "Brute Ratel C4 certificate (Unit 42 2022 cluster)",
}

// knownCertSerial maps decimal serial numbers. Serials alone collide easily
// (small integers), so only long or well-documented ones go here.
var knownCertSerial = map[string]string{
	"146473198": "Cobalt Strike default team-server certificate (serial 0x8BB00EE)",
	"476862511373535319627199034793753459614889484917": "Brute Ratel C4 certificate (Unit 42 2022 cluster)",
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
	if why, ok := knownCertSHA256[strings.ToLower(ci.SHA256)]; ok {
		return why, true
	}
	if why, ok := knownCertSerial[ci.Serial]; ok {
		return why, true
	}
	dn := strings.ToLower(ci.Subject + " " + ci.Issuer)
	if strings.Contains(dn, "major cobalt strike") || strings.Contains(dn, "o=cobaltstrike") || strings.Contains(dn, "advancedpentesting") {
		return "Cobalt Strike default certificate DN", true
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
