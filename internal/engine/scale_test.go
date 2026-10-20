package engine

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	sy "c2parser/internal/synth"
)

// v9c 3.2: flow-heavy scale scenario — ≥ 500k short connections (HTTP,
// TLS) + 200k DNS lookups + one periodic TLS series. Nightly / report path
// only:
//
//	C2PARSER_STRESS_REPORT=1 go test ./internal/engine -run TestScaleFlowHeavy -v -timeout 30m
//
// Reports throughput, peak RSS, RSS per connection and the rank of the
// periodic finding. C2PARSER_SCALE_CONNS overrides the connection count.
func TestScaleFlowHeavy(t *testing.T) {
	if os.Getenv("C2PARSER_STRESS_REPORT") == "" {
		t.Skip("set C2PARSER_STRESS_REPORT=1 for the flow-heavy scale run")
	}
	sc := sy.DefaultScale()
	if v := os.Getenv("C2PARSER_SCALE_CONNS"); v != "" {
		n, _ := strconv.Atoi(v)
		sc.Conns, sc.DNS = n, n*2/5
	}
	if v := os.Getenv("C2PARSER_LEAN_GC_MB"); v != "" {
		mb, _ := strconv.Atoi(v)
		defer func(old uint64) { LeanGCBytes = old }(LeanGCBytes)
		LeanGCBytes = uint64(mb) << 20
	}
	p := filepath.Join(t.TempDir(), "scale.pcap")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	bw := bufio.NewWriterSize(f, 1<<20)
	info, err := sy.WriteScale(bw, sc)
	if err != nil {
		t.Fatal(err)
	}
	bw.Flush()
	f.Close()
	st, _ := os.Stat(p)
	runtime.GC()
	base := maxRSS()
	t0 := time.Now()
	res, err := AnalyzeFile(p, Config{})
	if err != nil {
		t.Fatal(err)
	}
	wall := time.Since(t0)
	peak := maxRSS()
	rank := 0
	for i, f := range res.Findings {
		if f.Client == sc.NeedleClient {
			rank = i + 1
			break
		}
	}
	mb := float64(st.Size()) / (1 << 20)
	cur := scaleResult{Conns: info.TCPConns, Packets: info.Packets, WallSec: wall.Seconds(),
		MBps: mb / wall.Seconds(), PktPerSec: float64(info.Packets) / wall.Seconds(), ConnPerSec: float64(info.TCPConns) / wall.Seconds(),
		RSSPerConnKB: float64(peak-base) / 1024 / float64(info.TCPConns), PeakRSSMB: float64(peak) / (1 << 20), NeedleRank: rank}
	t.Logf("scale: %d packets, %d TCP conns, %d DNS pairs, %.0f MB", info.Packets, info.TCPConns, info.DNSPairs, mb)
	t.Logf("scale: %.1fs — %.0f kpkt/s, %.0f TCP connections/s, %.0f MB/s", wall.Seconds(), cur.PktPerSec/1000, cur.ConnPerSec, cur.MBps)
	t.Logf("scale: peak RSS %.0f MB (baseline %.0f MB) → %.2f KB per TCP connection", cur.PeakRSSMB, float64(base)/(1<<20), cur.RSSPerConnKB)
	t.Logf("scale: periodic finding rank %d of %d findings (series events dropped: %d, summary rows dropped: %d)", rank, len(res.Findings), countTruncated(res), res.Counters.SummaryRowsDropped)
	if rank == 0 || rank > 5 {
		t.Errorf("periodic needle ranked %d, want top 5", rank)
	}
	scaleGate(t, cur)
}

// scaleResult is one scale run (testdata/scale_baseline.json holds the
// recorded release numbers per connection count).
type scaleResult struct {
	Conns        int     `json:"conns"`
	Packets      int     `json:"packets"`
	WallSec      float64 `json:"wall_sec"`
	MBps         float64 `json:"mb_per_sec"`
	PktPerSec    float64 `json:"pkt_per_sec"`
	ConnPerSec   float64 `json:"conn_per_sec"`
	RSSPerConnKB float64 `json:"rss_per_conn_kb"`
	PeakRSSMB    float64 `json:"peak_rss_mb"`
	NeedleRank   int     `json:"needle_rank"`
	Machine      string  `json:"machine,omitempty"`
}

// scaleBaselineRelease is the release the nightly scale run is gated on.
const scaleBaselineRelease = "v9.0"

// v10a 0.2: fail the nightly run when connections/s or RSS per connection
// regresses by more than 20 % against the release baseline, or the needle
// ranks worse. C2PARSER_SCALE_WRITE=<name> records the current run instead
// (re-record on the nightly machine: the stored numbers are from the 2-vCPU
// sandbox, and throughput is machine-specific).
func scaleGate(t *testing.T, cur scaleResult) {
	path := "testdata/scale_baseline.json"
	all := map[string]map[string]scaleResult{}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &all); err != nil {
			t.Fatal(err)
		}
	}
	key := strconv.Itoa(cur.Conns / 1000 * 1000)
	if name := os.Getenv("C2PARSER_SCALE_WRITE"); name != "" {
		if all[name] == nil {
			all[name] = map[string]scaleResult{}
		}
		cur.Machine = fmt.Sprintf("%s/%s, %d CPUs", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
		all[name][key] = cur
		b, _ := json.MarshalIndent(all, "", "  ")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("recorded scale baseline %s @ %s connections", name, key)
		return
	}
	base, ok := all[scaleBaselineRelease][key]
	if !ok {
		t.Logf("no %s scale baseline at %s connections; not gated", scaleBaselineRelease, key)
		return
	}
	t.Logf("vs %s (%s): conns/s %.0f → %.0f, RSS/conn %.2f → %.2f KB, rank %d → %d",
		scaleBaselineRelease, base.Machine, base.ConnPerSec, cur.ConnPerSec, base.RSSPerConnKB, cur.RSSPerConnKB, base.NeedleRank, cur.NeedleRank)
	if cur.ConnPerSec < 0.8*base.ConnPerSec {
		t.Errorf("connections/s %.0f is > 20 %% below %s (%.0f)", cur.ConnPerSec, scaleBaselineRelease, base.ConnPerSec)
	}
	if cur.RSSPerConnKB > 1.2*base.RSSPerConnKB {
		t.Errorf("RSS per connection %.2f KB is > 20 %% above %s (%.2f KB)", cur.RSSPerConnKB, scaleBaselineRelease, base.RSSPerConnKB)
	}
	if cur.NeedleRank > base.NeedleRank {
		t.Errorf("periodic finding rank %d is worse than %s (%d)", cur.NeedleRank, scaleBaselineRelease, base.NeedleRank)
	}
}

// maxRSS is the process's peak resident set (bytes).
func maxRSS() int64 {
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "VmHWM:") {
				kb, _ := strconv.ParseInt(strings.Fields(l)[1], 10, 64)
				return kb << 10
			}
		}
	}
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return ru.Maxrss
}

func countTruncated(r *Result) int64 { return r.Counters.SeriesEventsDropped }
