package engine

import (
	"math"
	"strings"

	"c2parser/internal/stats"
)

// Positional profile of DNS labels. Encoders put fixed framing (message
// type, session id, sequence) at fixed offsets and encoded data after it:
// some tunnels prefix every name with a constant tag, dnscat2 with a hex
// session id, others carry a per-session header in the first encoded
// columns. A per-name or whole-domain entropy is diluted by that framing;
// looking position by position separates constant columns (framing) from
// varying columns, and asks whether the varying columns are as random as
// the encoding alphabet allows. Length-independent, so short labels aren't
// penalised the way per-name entropy is. Which prefix (if any) a given
// framework produces is a profile question, not an assumption of this
// profiler. The separate generic and snapshot-derived studies in
// sliverdns_test.go measure whether prefixes persist as session IDs and
// message types vary; neither presence nor absence identifies a framework.

type positional struct {
	Prefix    string           `json:"prefix,omitempty"` // constant framing at the start
	Constant  int              `json:"constant_positions"`
	Varying   int              `json:"varying_positions"`
	Ratio     float64          `json:"ratio"` // n-weighted mean H_pos / E[H_pos]
	Score     float64          `json:"score"`
	Remainder stats.Assessment `json:"remainder"` // aggregate randomness of varying positions only
}

const posMinSamples = 20

// dnsShapeCap is a mutation hook for the F07 query-shape correlation guard.
var dnsShapeCap = true

// dnsQueryShapeOnly identifies overlapping descriptions of the same query
// vocabulary: name/label length, its encoded-size estimate, symbol distribution,
// record types and cadence. Require both contributing length views so this
// guard addresses their amplification without changing unrelated DNS findings.
// Name novelty, response behavior, specific signatures, IOCs and any unknown
// contributing signal are separate evidence and prevent the shape-only cap.
func dnsQueryShapeOnly(sigs []stats.Signal) bool {
	longName, longLabel := false, false
	for _, s := range sigs {
		if s.Contribution() < negligible {
			continue
		}
		switch s.Name {
		case "long_names":
			longName = true
		case "long_labels":
			longLabel = true
		case "unique_subdomains", "positional_randomness", "framing_prefix", "tunnel_record_types", "encoded_volume":
		default:
			if stats.FamilyOf(s.Name) != "timing" {
				return false
			}
		}
	}
	return longName && longLabel
}

// dnsCardinalityFloor is the distinct-names-per-logical-query ratio below
// which a domain repeats its names: name_cardinality_ratio starts scoring
// above it ("tunnels ≈ 1, normal domains ≪ 0.4").
const dnsCardinalityFloor = 0.4

// dnsNameReuse reports measured name reuse: fewer than dnsCardinalityFloor
// distinct names per logical query. It is a direct count of repeats, so it
// needs no minimum volume (retries are already folded into logical
// queries; unique ≤ logical, so no queries means no reuse). Not measurable
// once the distinct-name set has hit maxUniqueSubs: the ratio would fall for
// a huge all-unique tunnel. R-01: the F07 shape cap requires this; the
// absence of a novelty signal (< 20 logical queries) is not evidence of reuse.
func dnsNameReuse(logical, unique int) bool {
	return unique < maxUniqueSubs && float64(unique) < dnsCardinalityFloor*float64(logical)
}

func positionalProfile(labels []string) positional {
	var p positional
	if len(labels) < posMinSamples {
		return p
	}
	maxLen := 0
	for _, l := range labels {
		if len(l) > maxLen {
			maxLen = len(l)
		}
	}
	if maxLen > 63 {
		maxLen = 63
	}
	type col struct {
		h      stats.Histogram
		top    uint64
		topSym byte
	}
	cols := make([]col, maxLen)
	for _, l := range labels {
		l = strings.ToLower(l)
		for i := 0; i < len(l) && i < maxLen; i++ {
			cols[i].h.Counts[l[i]]++
			cols[i].h.N++
		}
	}
	var rem stats.Histogram
	prefixOpen := true
	var prefix []byte
	var varying []int
	for i := range cols {
		c := &cols[i]
		if c.h.N < posMinSamples {
			break
		}
		for s, n := range c.h.Counts {
			if n > c.top {
				c.top, c.topSym = n, byte(s)
			}
		}
		if float64(c.top) >= 0.9*float64(c.h.N) {
			p.Constant++
			if prefixOpen {
				prefix = append(prefix, c.topSym)
			}
			continue
		}
		prefixOpen = false
		varying = append(varying, i)
		rem.Merge(&c.h)
	}
	p.Prefix = string(prefix)
	p.Varying = len(varying)
	if p.Varying == 0 {
		return p
	}
	p.Remainder = stats.Assess(&rem)
	k := p.Remainder.Alphabet.Size()
	var num, den float64
	for _, i := range varying {
		c := &cols[i]
		a := stats.Assess(&c.h)
		mean, _ := stats.NullEntropy(k, int(c.h.N))
		if mean <= 0 {
			continue
		}
		w := float64(c.h.N)
		num += w * math.Min(1, a.Entropy/mean)
		den += w
	}
	if den > 0 {
		p.Ratio = num / den
	}
	// Random columns sit at ≈1.0; hostnames/words at ≈0.6–0.8.
	p.Score = stats.Clamp01((p.Ratio - 0.82) / 0.13)
	return p
}
