package engine

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// Metamorphic invariants at the engine level (stress doc §G): shifting all
// timestamps, or renumbering IPs consistently, must not change any score.
func scoreSet(res *Result, from, to []string) []string {
	var out []string
	for _, f := range res.Findings {
		title := f.Title
		for i := range from {
			title = strings.ReplaceAll(title, to[i], from[i])
		}
		out = append(out, fmt.Sprintf("%s|%s|%.2f", f.Category, title, f.Score))
	}
	sort.Strings(out)
	return out
}

func TestEngineMetamorphic(t *testing.T) {
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		build := func(shift time.Duration, cl, sv string) *Result {
			s := newSynth(t)
			s.now = s.now.Add(shift)
			periodicHTTP(s, cl, sv, "status.example", 50, 9)
			return s.analyze(cfg)
		}
		base := scoreSet(build(0, "10.7.0.10", "203.0.113.90"), nil, nil)
		if len(base) == 0 {
			t.Fatal("no findings in base case")
		}
		shifted := scoreSet(build(400*24*time.Hour, "10.7.0.10", "203.0.113.90"), nil, nil)
		renum := scoreSet(build(0, "10.8.1.20", "198.51.100.200"),
			[]string{"10.7.0.10", "203.0.113.90"}, []string{"10.8.1.20", "198.51.100.200"})
		for name, got := range map[string][]string{"time shift": shifted, "IP renumber": renum} {
			if strings.Join(got, "\n") != strings.Join(base, "\n") {
				t.Errorf("v2=%v %s changed findings:\n%v\nvs\n%v", cfg.TimingV2, name, base, got)
			}
		}
	}
}
