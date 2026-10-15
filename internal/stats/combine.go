package stats

import "sort"

// Signal is one piece of evidence. Score is how strongly the evidence is
// present (0..1); Weight is how much that evidence alone would convince us
// (0..1). Keeping them separate makes every finding explainable.
type Signal struct {
	Name   string  `json:"name"`
	Score  float64 `json:"score"`
	Weight float64 `json:"weight"`
	Detail string  `json:"detail,omitempty"`
	Family string  `json:"family,omitempty"` // set by AssignFamilies (timing v2 scoring)
}

// Contribution is Score×Weight, clamped.
func (s Signal) Contribution() float64 { return clamp01(s.Score) * clamp01(s.Weight) }

// NoisyOR combines independent pieces of evidence:
//
//	P = 1 − Π (1 − wᵢ·sᵢ)
//
// One strong signal is enough to raise the score; several weak ones add up
// without ever exceeding 1; zero-score signals have no effect.
func NoisyOR(sigs []Signal) float64 {
	p := 1.0
	for _, s := range sigs {
		p *= 1 - s.Contribution()
	}
	return 1 - p
}

// Severity buckets a combined score.
func Severity(score float64) string {
	switch {
	case score >= 0.85:
		return "critical"
	case score >= 0.65:
		return "high"
	case score >= 0.4:
		return "medium"
	case score >= 0.2:
		return "low"
	}
	return "info"
}

// SeverityRank orders severities for filtering.
func SeverityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// SortSignals orders by contribution, strongest first.
func SortSignals(s []Signal) {
	// Ties by name: signals arrive from a map, and equal contributions used
	// to come out in random order from run to run (v9c).
	sort.SliceStable(s, func(i, j int) bool {
		ci, cj := s[i].Contribution(), s[j].Contribution()
		if ci != cj {
			return ci > cj
		}
		return s[i].Name < s[j].Name
	})
}
