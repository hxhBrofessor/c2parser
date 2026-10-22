package engine

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

// FIX-D1: scoreDNS iterated e.dns.domains and dnsDomain.clients in map
// order, so -timing v2 timing_series order, the named client on beacon
// ties and the order of equal-score DNS findings changed run to run.

// analyzeRuns writes the capture once and analyzes the same path n times,
// returning each marshaled Result.
func analyzeRuns(t *testing.T, s *synth, cfg Config, n int) ([][]byte, []*Result) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "synth.pcap")
	if err := os.WriteFile(p, s.buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	var rs []*Result
	for i := 0; i < n; i++ {
		res, err := AnalyzeFile(p, cfg)
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		out, rs = append(out, b), append(rs, res)
	}
	return out, rs
}

// dnsBeacon sends n tunnel-shaped TXT queries for *.base from client every
// ~period s. Subdomains come from seed, so equal seeds give equal names.
func dnsBeacon(s *synth, client, base string, n int, period float64, seed uint64, id *uint16) {
	r := mrand.New(mrand.NewPCG(seed, seed))
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding)
	ts := s.now
	for i := 0; i < n; i++ {
		ts = ts.Add(time.Duration(period * (1 + 0.1*(2*r.Float64()-1)) * float64(time.Second)))
		raw := make([]byte, 20)
		for j := range raw {
			raw[j] = byte(r.Uint32())
		}
		name := fmt.Sprintf("%s.%s", strings.ToLower(b32.EncodeToString(raw)), base)
		s.dnsQuery(ts, client, "10.6.0.53", name, layers.DNSTypeTXT, *id)
		s.dnsResp(ts.Add(20*time.Millisecond), client, "10.6.0.53", name, layers.DNSTypeTXT, *id, layers.DNSResponseCodeNoErr,
			[]layers.DNSResourceRecord{{Name: []byte(name), Type: layers.DNSTypeTXT, Class: layers.DNSClassIN, TTL: 0,
				TXTs: [][]byte{[]byte("ok")}}})
		*id++
	}
}

// determinismCapture: 24 DNS domains × 3 clients, one HTTP beacon and one
// long-held TLS channel.
func determinismCapture(t *testing.T) *synth {
	s := newSynth(t)
	id := uint16(1)
	for d := 0; d < 24; d++ {
		for c := 0; c < 3; c++ {
			dnsBeacon(s, fmt.Sprintf("10.6.1.%d", 10+c), fmt.Sprintf("d%02d-sync.example", d), 30, 20+float64(d), uint64(100*d+c+1), &id)
		}
	}
	periodicHTTP(s, "10.6.2.10", "203.0.113.90", "status.example", 40, 9)
	ts := s.now
	c := s.tcp(ts, "10.6.2.11", 53100, "198.51.100.90", 443)
	ts = c.Send(ts.Add(5*time.Millisecond), true, clientHello("sync.example", []string{"h2"}), 1400)
	ts = c.Send(ts.Add(20*time.Millisecond), false, appData(400), 1400)
	for i := 0; i < 40; i++ {
		ts = ts.Add(time.Duration(45 * (1 - 0.05*float64(i%3)) * float64(time.Second)))
		ts = c.Send(ts, true, appData(35), 1400)
		ts = c.Send(ts.Add(20*time.Millisecond), false, appData(85), 1400)
	}
	c.Close(ts.Add(time.Second))
	return s
}

func requireIdentical(t *testing.T, runs [][]byte) {
	t.Helper()
	for i := 1; i < len(runs); i++ {
		if !bytes.Equal(runs[0], runs[i]) {
			n := 0
			for n < len(runs[0]) && n < len(runs[i]) && runs[0][n] == runs[i][n] {
				n++
			}
			lo := max(0, n-80)
			t.Fatalf("run %d differs from run 0 at byte %d:\n run0: …%s…\n run%d: …%s…", i, n,
				runs[0][lo:min(len(runs[0]), n+80)], i, runs[i][lo:min(len(runs[i]), n+80)])
		}
	}
}

// T-D1
func TestTimingV2Deterministic(t *testing.T) {
	s := determinismCapture(t)
	runs, rs := analyzeRuns(t, s, Config{TimingV2: true}, 10)
	sites := map[string]int{}
	for _, ts := range rs[0].Timing {
		sites[ts.Site]++
	}
	if sites["dns"] < 60 || sites["http"] == 0 || sites["channel"] == 0 {
		t.Fatalf("fixture does not cover dns ≥ 60, http and channel series: %v", sites)
	}
	requireIdentical(t, runs)
}

// T-D1v1
func TestTimingV1Deterministic(t *testing.T) {
	s := determinismCapture(t)
	runs, rs := analyzeRuns(t, s, Config{}, 10)
	if len(rs[0].DNS) < 20 {
		t.Fatalf("fixture has %d DNS domains", len(rs[0].DNS))
	}
	requireIdentical(t, runs)
}

// T-D2: two clients with identical query series for one domain tie on
// beacon strength; the finding names the lower address (OD-D1).
func TestDNSBestClientTieBreak(t *testing.T) {
	for _, cfg := range []Config{{TimingV2: true}, {}} {
		s := newSynth(t)
		id := uint16(1)
		// Higher address first in the capture, so first-seen order can't
		// stand in for the tie-break.
		dnsBeacon(s, "10.6.3.20", "tie-tunnel.example", 40, 30, 77, &id)
		dnsBeacon(s, "10.6.3.9", "tie-tunnel.example", 40, 30, 77, &id)
		_, rs := analyzeRuns(t, s, cfg, 10)
		for i, res := range rs {
			f := findBy(res, CatDNS, "tie-tunnel.example")
			if f == nil {
				t.Fatalf("v2=%v run %d: no DNS finding", cfg.TimingV2, i)
			}
			if !strings.Contains(f.Title, "(client 10.6.3.9)") {
				t.Errorf("v2=%v run %d: title %q, want the lower address 10.6.3.9", cfg.TimingV2, i, f.Title)
			}
		}
	}
}

// T-D3: two DNS findings with equal score keep a stable relative order.
func TestDNSEqualScoreFindingOrder(t *testing.T) {
	for _, cfg := range []Config{{TimingV2: true}, {}} {
		s := newSynth(t)
		id := uint16(1)
		var bases []string
		for d := 0; d < 6; d++ {
			base := fmt.Sprintf("eq%d-tunnel.example", d)
			bases = append(bases, base)
			dnsBeacon(s, "10.6.4.10", base, 40, 30, 55, &id)
		}
		_, rs := analyzeRuns(t, s, cfg, 10)
		var want []string
		for i, res := range rs {
			var got []string
			score := -1.0
			for _, f := range res.Findings {
				if f.Category != CatDNS {
					continue
				}
				if score >= 0 && f.Score != score {
					t.Fatalf("v2=%v run %d: fixture scores differ (%v vs %v); not an equal-score fixture", cfg.TimingV2, i, f.Score, score)
				}
				score = f.Score
				got = append(got, f.Title)
			}
			if len(got) != len(bases) {
				t.Fatalf("v2=%v run %d: %d DNS findings, want %d: %v", cfg.TimingV2, i, len(got), len(bases), got)
			}
			if i == 0 {
				want = got
				continue
			}
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("v2=%v run %d: order\n%v\nwant\n%v", cfg.TimingV2, i, got, want)
			}
		}
	}
}
