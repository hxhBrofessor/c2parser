package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

// FIX-D1b (v11.1): the NXDOMAIN-spread loop iterated the e.dns.clients map,
// so equal-score DGA findings were registered, and so ordered, by map order.
// Six clients with identical NXDOMAIN patterns give six equal-score
// findings; their order must not change between runs.
func TestNXDomainSpreadFindingOrder(t *testing.T) {
	s := newSynth(t)
	for c := 0; c < 6; c++ {
		cl := fmt.Sprintf("10.8.0.%d", 10+c)
		for i := 0; i < 8; i++ {
			name := fmt.Sprintf("q%d.nx%02d.org", c, i)
			ts := s.now.Add(time.Duration(c*100+i) * time.Second)
			s.dnsQuery(ts, cl, "10.0.0.53", name, layers.DNSTypeA, uint16(c*10+i))
			s.dnsResp(ts.Add(10*time.Millisecond), cl, "10.0.0.53", name, layers.DNSTypeA, uint16(c*10+i), layers.DNSResponseCodeNXDomain, nil)
		}
	}
	order := func(r *Result) string {
		var titles []string
		for _, f := range r.Findings {
			if f.Category == CatDGA {
				titles = append(titles, f.Title)
			}
		}
		return strings.Join(titles, "\n")
	}
	_, results := analyzeRuns(t, s, Config{}, 10)
	// The fixture must really produce ties: every NXDOMAIN-spread finding
	// has the same score, so only iteration order could separate them.
	var scores []float64
	for _, f := range results[0].Findings {
		if f.Category == CatDGA {
			scores = append(scores, f.Score)
		}
	}
	if len(scores) < 2 {
		t.Fatalf("fixture: %d NXDOMAIN-spread findings, want >= 2", len(scores))
	}
	for _, sc := range scores[1:] {
		if sc != scores[0] {
			t.Fatalf("fixture: NXDOMAIN-spread scores not all equal: %v", scores)
		}
	}
	first := order(results[0])
	if strings.Count(first, "\n") < 1 {
		t.Fatalf("fixture: want >= 2 NXDOMAIN-spread findings, got %q", first)
	}
	for i := 1; i < len(results); i++ {
		if got := order(results[i]); got != first {
			t.Fatalf("run %d: NXDOMAIN-spread finding order changed:\n%s\nvs run 0:\n%s", i, got, first)
		}
	}
}
