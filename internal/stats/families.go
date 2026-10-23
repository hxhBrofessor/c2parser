package stats

import (
	"sort"
	"strings"
)

// Signal families (c2parser v8, spec Q3.0). Signals inside one family are
// correlated views of the same evidence (three UA oddities are one fact
// about one header), so they combine by max plus a damped second-strongest
// (×familyDamp); families then combine by noisy-OR. Signals that belong to
// no named family are their own family, which reproduces plain noisy-OR.

const familyDamp = 0.3

// familyCaps bounds a family's contribution. Generic UA oddities are weak,
// common in benign software, and must stay below medium on their own.
var familyCaps = map[string]float64{"ua": 0.35}

// FamilyOf maps a signal name to its family; a signal with no named
// family is its own family.
func FamilyOf(name string) string {
	f, _ := familyOf(name)
	return f
}

// Unmapped reports whether a signal has no named family (v10a.1 D2). Such
// signals still score as their own family; ReportedFamilyScores groups
// them under UnmappedFamily so calibration sees them as one, labelled set
// rather than as many silent single-signal families.
func Unmapped(name string) bool {
	_, ok := familyOf(name)
	return !ok
}

// UnmappedFamily is the family_scores key for signals with no named family.
const UnmappedFamily = "unmapped"

// FixedURITimingFamily maps uri_shape:fixed-uri to the timing family so a
// fixed-URI shape rides inside the timing-only cap (v11a N2). Var so the
// mutation test can prove the cap depends on the mapping.
var FixedURITimingFamily = true

func familyOf(name string) (string, bool) {
	switch {
	case name == "hdr:ua_c2_default", strings.HasPrefix(name, "default_profile:"), name == "c2_default_certificate",
		name == "cs_dns_defaults", name == "c2_default_pipe_name", strings.HasPrefix(name, "cs_config:"):
		return "default_profile", true
	case strings.HasPrefix(name, "hdr:ua_"):
		return "ua", true
	case name == "hdr:invalid_request_content_type", name == "hdr:post_to_ip_literal", name == "hdr:no_cache_post",
		strings.HasPrefix(name, "uri_shape:") && name != "uri_shape:fixed-uri":
		// correlated quirks of one client implementation (v8a review #5);
		// URI shapes are the same class of structural client habit (v11a N2)
		return "http_client_quirks", true
	case name == "uri_shape:fixed-uri":
		// One URI repeated on a beacon describes the *timing* shape, not the
		// payload; it must not lift a fleet/poller/scheduler-capped beacon
		// above its cap (v11a N2), so it rides the timing family.
		if FixedURITimingFamily {
			return "timing", true
		}
		return "http_client_quirks", true
	case name == "random_payloads", name == "legacy_entropy_threshold", name == "random_pipe_data", name == "random_ws_payloads":
		return "payload_randomness", true
	case strings.HasPrefix(name, "encoded_payload_in_"), name == "sig:mythic-agent-message",
		name == "mythic_message_in_pipe", name == "pivot_frame_header", name == "length_residue":
		// structural payload evidence — *what* carries the data and how it is
		// framed — as distinct from entropy (payload_randomness), which says
		// how random it looks (v11a). These sat unmapped in v10 (each its
		// own family); one family only reduces their combined lift.
		return "payload_shape", true
	case name == "beacon_timing", strings.HasPrefix(name, "timing_"):
		return "timing", true
	case strings.HasPrefix(name, "cert_"), name == "self_signed_certificate", name == "fresh_certificate",
		name == "expired_certificate", name == "certificate_name_mismatch":
		return "cert", true
	case strings.HasPrefix(name, "sigma:"):
		return "sigma", true
	case name == "wireguard_shape_on_dns_port":
		return "transport_anomaly", true
	case strings.HasPrefix(name, "ldap_"), name == "samr_enumeration", name == "tsts_session_enum":
		return "recon", true
	case name == "dcsync_from_non_dc":
		return "credential_access", true
	case name == "dc_replication":
		return "info", true
	case name == "pivot_from_c2_host", name == "recon_from_c2_host", name == "relay_timing":
		return "correlation", true
	}
	return name, false
}

// AssignFamilies fills Family on every signal.
func AssignFamilies(s []Signal) {
	for i := range s {
		s[i].Family = FamilyOf(s[i].Name)
	}
}

// FamilyScores returns each family's combined contribution.
func FamilyScores(sigs []Signal) map[string]float64 {
	by := map[string][]float64{}
	for _, s := range sigs {
		f := s.Family
		if f == "" {
			f = FamilyOf(s.Name)
		}
		by[f] = append(by[f], s.Contribution())
	}
	out := make(map[string]float64, len(by))
	for f, cs := range by {
		sort.Sort(sort.Reverse(sort.Float64Slice(cs)))
		v := cs[0]
		if len(cs) > 1 {
			v = 1 - (1-v)*(1-familyDamp*cs[1])
		}
		if c, ok := familyCaps[f]; ok && v > c {
			v = c
		}
		out[f] = v
	}
	return out
}

// ReportedFamilyScores is FamilyScores for output: families of
// unmapped signals are merged under UnmappedFamily by noisy-OR, which is
// exactly their joint effect on NoisyORFamilies (each is its own family),
// so the reported families still multiply out to the score.
func ReportedFamilyScores(sigs []Signal) map[string]float64 {
	var mapped, unmapped []Signal
	for _, s := range sigs {
		if Unmapped(s.Name) {
			unmapped = append(unmapped, s)
		} else {
			mapped = append(mapped, s)
		}
	}
	out := FamilyScores(mapped)
	if len(unmapped) > 0 {
		out[UnmappedFamily] = NoisyORFamilies(unmapped)
	}
	return out
}

// NoisyORFamilies combines family scores by noisy-OR.
func NoisyORFamilies(sigs []Signal) float64 {
	p := 1.0
	for _, v := range FamilyScores(sigs) {
		p *= 1 - v
	}
	return 1 - p
}
