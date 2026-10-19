package engine

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"c2parser/internal/stats"
)

// Cobalt Strike DNS beacon defaults (Fortra "DNS Beacons" docs; SigmaHQ
// net_dns_mal_cobaltstrike.yml). Each feature alone is weak — "api." and
// "www." are everywhere — so the signal needs a conjunction:
//
//   - the stager marker (".stage.123456.", "aaa.stage.") — enough alone;
//   - request prefixes cdn./www6./api./www./post. followed by a hex label
//     (A / AAAA / TXT tasking, metadata, output), plus a second feature;
//   - the idle answer 0.0.0.0 together with TTL 1 (an untasked beacon only
//     ever asks for <id>.domain and gets exactly this back).

var csDNSPrefixSet = map[string]bool{"cdn": true, "www6": true, "api": true, "www": true, "post": true}

func csStageMarker(name string) bool {
	return strings.Contains("."+name+".", ".stage.123456.") || strings.HasPrefix(name, "aaa.stage.")
}

func isHexLabel(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// csDNSPrefix matches a subdomain shaped <prefix>.<hex ≥6>.… (at least
// three labels below the registrable domain: prefix, data/nonce, id).
func csDNSPrefix(sub string) (string, bool) {
	l := strings.Split(sub, ".")
	if len(l) < 3 || !csDNSPrefixSet[l[0]] || len(l[1]) < 6 || !isHexLabel(l[1]) {
		return "", false
	}
	return l[0], true
}

// csDNSSignal scores a domain against the Cobalt Strike DNS defaults.
func csDNSSignal(d *dnsDomain) (stats.Signal, bool) {
	var parts []string
	miss := 1.0
	add := func(s float64, what string) {
		miss *= 1 - s
		parts = append(parts, what)
	}
	stage := d.csStage > 0
	prefix := d.csPrefixNames >= 3
	multi := len(d.csPrefixes) >= 2
	zero := d.aAnswers >= 3 && float64(d.zeroA)/float64(d.aAnswers) >= 0.5
	ttl1 := d.answerRRs >= 3 && float64(d.ttl1)/float64(d.answerRRs) >= 0.5
	if stage {
		add(0.9, fmt.Sprintf("%d stager-marker names", d.csStage))
	}
	if prefix {
		add(0.5, fmt.Sprintf("%d unique <prefix>.<hex>… names", d.csPrefixNames))
	}
	if multi {
		pf := make([]string, 0, len(d.csPrefixes))
		for p := range d.csPrefixes {
			pf = append(pf, p+".")
		}
		sort.Strings(pf)
		add(0.25, "prefixes "+strings.Join(pf, " "))
	}
	if zero {
		add(0.35, fmt.Sprintf("%d/%d A answers are 0.0.0.0", d.zeroA, d.aAnswers))
	}
	if ttl1 {
		add(0.3, fmt.Sprintf("%d/%d answers have TTL 1", d.ttl1, d.answerRRs))
	}
	if !(stage || prefix && (multi || zero || ttl1) || zero && ttl1) {
		return stats.Signal{}, false
	}
	detail := "Cobalt Strike DNS beacon defaults: " + strings.Join(parts, "; ")
	if d.csSample != "" {
		detail += "; e.g. " + d.csSample
	}
	return stats.Signal{Name: "cs_dns_defaults", Weight: 0.9, Score: math.Round((1-miss)*100) / 100, Detail: detail}, true
}
