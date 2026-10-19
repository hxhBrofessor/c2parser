// Package report renders engine results for humans (text) and machines (JSON).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"c2parser/internal/engine"
	"c2parser/internal/stats"
)

// Options control text rendering.
type Options struct {
	MinScore float64
	Verbose  bool
}

// JSON writes every result as a JSON array.
func JSON(w io.Writer, results []*engine.Result, o Options) error {
	filtered := make([]*engine.Result, 0, len(results))
	for _, r := range results {
		c := *r
		c.Findings = nil
		for _, f := range r.Findings {
			if f.Score >= o.MinScore {
				c.Findings = append(c.Findings, f)
			}
		}
		if c.Findings == nil {
			c.Findings = []engine.Finding{}
		}
		filtered = append(filtered, &c)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(filtered)
}

// CandidateJSON writes the opt-in alternate-decoding sidecar. It is a
// separate schema and never augments the established result JSON.
func CandidateJSON(w io.Writer, reports []engine.DecodeCandidateReport) error {
	if reports == nil {
		reports = []engine.DecodeCandidateReport{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(reports)
}

// Text writes an analyst-oriented report.
func Text(w io.Writer, r *engine.Result, o Options) {
	c := r.Counters
	fmt.Fprintf(w, "══ %s\n", r.File)
	fmt.Fprintf(w, "   %s → %s (%.0fs) | %d packets, %d TCP conns, %d UDP flows | %d HTTP msgs, %d SMB msgs, %d DNS queries\n",
		r.Start, r.End, r.DurationSec, c.Packets, c.TCPConns, c.UDPFlows, c.HTTPMessages, c.SMBMessages, c.DNSQueries)

	var shown []engine.Finding
	for _, f := range r.Findings {
		if f.Score >= o.MinScore {
			shown = append(shown, f)
		}
	}
	counts := map[string]int{}
	for _, f := range shown {
		counts[f.Severity]++
	}
	fmt.Fprintf(w, "   findings ≥ %.2f: %d (critical %d, high %d, medium %d, low %d)\n\n",
		o.MinScore, len(shown), counts["critical"], counts["high"], counts["medium"], counts["low"])

	if len(r.Hosts) > 0 {
		fmt.Fprintln(w, "   host risk (cumulative across findings):")
		for _, h := range r.Hosts {
			if h.Risk < o.MinScore {
				continue
			}
			var cats []string
			for c, n := range h.Categories {
				cats = append(cats, fmt.Sprintf("%s×%d", c, n))
			}
			sort.Strings(cats)
			fmt.Fprintf(w, "     %-16s %-8s %.2f  %d findings: %s\n", h.Host, strings.ToUpper(h.Severity), h.Risk, h.Findings, strings.Join(cats, ", "))
		}
		fmt.Fprintln(w)
	}
	for i, f := range shown {
		fmt.Fprintf(w, "[%d] %-8s %.2f  %s\n", i+1, strings.ToUpper(f.Severity), f.Score, f.Title)
		fmt.Fprintf(w, "    category: %s", f.Category)
		if len(f.ServerNames) > 0 {
			fmt.Fprintf(w, " | server names: %s", strings.Join(f.ServerNames, ", "))
		}
		if f.First != "" {
			fmt.Fprintf(w, " | %s → %s", f.First, f.Last)
		}
		fmt.Fprintln(w)
		for _, s := range f.Signals {
			if s.Contribution() < 0.01 && !o.Verbose {
				continue
			}
			fmt.Fprintf(w, "    • %-34s %.2f×%.2f  %s\n", s.Name, s.Score, s.Weight, s.Detail)
		}
		for _, ev := range f.Evidence {
			fmt.Fprintf(w, "    · %s\n", ev)
		}
		if len(f.Frames) > 0 {
			fr := make([]string, len(f.Frames))
			for j, n := range f.Frames {
				fr[j] = fmt.Sprint(n)
			}
			fmt.Fprintf(w, "    ↳ frames: %s   (Wireshark: frame.number in {%s})\n", strings.Join(fr, ", "), strings.Join(fr, " "))
		}
		fmt.Fprintln(w)
	}
	if len(shown) == 0 {
		fmt.Fprintln(w, "   no findings above threshold")
		fmt.Fprintln(w)
	}
	if !o.Verbose {
		return
	}
	fmt.Fprintln(w, "── HTTP channels")
	for i, h := range r.HTTP {
		if i == 12 {
			break
		}
		b := "-"
		if h.Beacon != nil {
			b = fmt.Sprintf("%.2f (median %.2fs, jitter %.0f%%)", h.Beacon.Score, h.Beacon.MedianSec, h.Beacon.JitterPct)
		}
		fmt.Fprintf(w, "   %s → %s:%d %-28s req %-5d up %-10s down %-10s random %d/%d legacy≥%.1f:%d beacon %s\n",
			h.Client, h.Server, h.Port, trunc(h.Host, 28), h.Requests, human(h.UploadB), human(h.DownloadB), h.RandomUp, h.RandomDown, 7.8, h.LegacyHits, b)
	}
	fmt.Fprintln(w, "── SMB files / pipes")
	for i, p := range r.Pipes {
		if i == 12 {
			break
		}
		kind := "file"
		if p.Pipe {
			kind = "pipe"
		}
		fmt.Fprintf(w, "   %s → %s %-4s %s\\%s  w %s r %s magic %d\n", p.Client, p.Server, kind, p.Share, strings.TrimLeft(p.Name, `\`), human(p.WriteBytes), human(p.ReadBytes), p.C2Magic)
	}
	fmt.Fprintln(w, "── DNS domains (by unique subdomains)")
	for i, d := range r.DNS {
		if i == 10 {
			break
		}
		fmt.Fprintf(w, "   %-32s q %-5d uniq %-5d avglen %-5.1f maxlabel %-3d %s rand %.2f enc≈%s nx %d\n",
			trunc(d.Domain, 32), d.Queries, d.UniqueSubs, d.AvgSubLen, d.MaxLabel, d.Alphabet, d.Randomness, human(d.EncodedBytes), d.NXDomain)
	}
	fmt.Fprintln(w, "── top talkers")
	for _, t := range r.TopTalkers {
		extra := ""
		if t.JA4 != "" {
			extra = " ja4 " + t.JA4
		}
		if t.QUIC {
			extra += " quic"
		}
		fmt.Fprintf(w, "   %s → %s:%d/%s %-30s conns %-4d out %-10s in %-10s PCR %+.2f longest %.0fs%s\n", t.Client, t.Server, t.Port, t.Proto,
			trunc(strings.Join(t.ServerNames, ","), 30), t.Conns, human(t.OutBytes), human(t.InBytes), t.PCR, t.LongestSec, extra)
	}
	fmt.Fprintln(w)
}

// MaxSeverity returns the highest severity among findings ≥ minScore.
func MaxSeverity(results []*engine.Result, minScore float64) string {
	best := "info"
	for _, r := range results {
		for _, f := range r.Findings {
			if f.Score >= minScore && stats.SeverityRank(f.Severity) > stats.SeverityRank(best) {
				best = f.Severity
			}
		}
	}
	return best
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func human(n int64) string {
	f := float64(n)
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2fGB", f/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2fMB", f/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKB", f/(1<<10))
	}
	return fmt.Sprintf("%dB", n)
}
