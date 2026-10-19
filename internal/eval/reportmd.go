package eval

import (
	"fmt"
	"sort"
	"strings"
)

// Markdown renders report.md: the same numbers as report.json, in the
// order a reader needs them, with every rate carrying its interval.
func (r *Report) Markdown() string {
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	p("# c2parser evaluation report\n\n")
	if r.Banner != "" {
		p("> **%s**\n\n", r.Banner)
	}
	if r.Refusal != "" {
		p("**%s**\n\n", r.Refusal)
	}
	p("%d units, %d timing series (%d C2, %d benign), %.1f benign host-hours.\n\n", len(r.Units), len(r.Series), r.C2Series, r.BenignSeries, r.BenignHostHours)
	verdict := "not eligible"
	if r.FlipGate.Eligible {
		verdict = "data floor met"
	}
	p("Default-flip data gate (≥ %d benign series, real data): **%s** — %s.\n\n", r.FlipGate.Required, verdict, r.FlipGate.Reason)
	for _, n := range r.Notes {
		p("- Note: %s\n", n)
	}
	if len(r.Notes) > 0 {
		p("\n")
	}

	p("## Units\n\n| Unit | Role | Files | Duration | Benign host-hours | Series | Labels | Zeek join (matched / unmatched-zeek / unmatched-c2parser / ambiguous) |\n|---|---|---|---|---|---|---|---|\n")
	for _, u := range r.Units {
		join := "—"
		if j := u.Join; j != nil {
			join = fmt.Sprintf("%d / %d / %d / %d (%.1f %%; C2 %d of %d)", j.Matched, j.UnmatchedZeek, j.UnmatchedC2P, j.Ambiguous, 100*j.Rate, j.PosMatched, j.Positives)
		}
		hh := fmt.Sprintf("%.1f", u.BenignHostHours)
		if u.ExpectedHostHours > 0 {
			hh += fmt.Sprintf(" (expected %.1f)", u.ExpectedHostHours)
		}
		p("| %s | %s | %d | %.1f h | %s | %d | %s | %s |\n", u.Name, u.Role, u.Files, u.DurationSec/3600, hh, u.Series, u.LabelSource, join)
	}

	p("\n## Scorers: v1 vs v2 vs RITA-like\n\n")
	if len(r.Thresholds) == 0 {
		p("No operating points (see above).\n\n")
	} else {
		p("Operating point: the benign 1 − 10⁻⁴ quantile of each score. TPR over all C2 series; FP per benign host-hour at that point (95 %% intervals).\n\n| Scorer | Threshold | TPR | FP / host-hour | Worst held-out framework |\n|---|---|---|---|---|\n")
		for _, c := range r.Comparison {
			if c.Threshold == nil {
				continue
			}
			p("| %s | %.3f | %s | %s | %s |\n", c.Scorer, *c.Threshold, propStr(c.TPR), rateStr(c.FPPerHH), orDash(c.WorstHeldOut))
		}
		p("\n")
	}

	if len(r.JitterTPR) > 0 {
		p("## TPR per jitter cell at the operating point\n\n| Jitter | v1 | v2 | RITA-like | n ≥ k |\n|---|---|---|---|---|\n")
		js := sortedKeysOf(r.JitterTPR)
		sort.Slice(js, func(a, b int) bool { return jitterOrder(js[a]) < jitterOrder(js[b]) })
		for _, j := range js {
			m := r.JitterTPR[j]
			p("| %s | %s | %s | %s | %s |\n", j, propV(m, "v1"), propV(m, "v2"), propV(m, "rita_like"), propV(m, "n_ge_k"))
		}
		p("\n")
	}
	if len(r.JitterCurve) > 0 {
		p("## Detection vs jitter (detection_vs_jitter.csv)\n\nMean / median score of C2 series per jitter cell")
		if len(r.Thresholds) > 0 {
			p("; TPR in the CSV")
		}
		p(".\n\n| Jitter | Scorer | n | Mean | Median |\n|---|---|---|---|---|\n")
		for _, j := range r.JitterCurve {
			p("| %s | %s | %d | %.3f | %.3f |\n", j.Jitter, j.Scorer, j.N, j.Mean, j.Median)
		}
		p("\n")
	}
	if len(r.Cells) > 0 {
		p("## TPR per cell (framework / transport / sleep / jitter)\n\n| Cell | v1 | v2 | RITA-like | n ≥ k |\n|---|---|---|---|---|\n")
		for _, c := range sortedKeysOf(r.CellCI) {
			m := r.CellCI[c]
			p("| %s | %s | %s | %s | %s |\n", c, propV(m, "v1"), propV(m, "v2"), propV(m, "rita_like"), propV(m, "n_ge_k"))
		}
		p("\n")
	}

	p("## Benign findings per host-hour, by severity\n\n")
	if len(r.FPBySeverity) == 0 {
		p("No benign host-hours.\n\n")
	} else {
		p("| Severity | Findings | Per host-hour (95 %% CI) |\n|---|---|---|\n")
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			x := r.FPBySeverity[sev]
			p("| %s | %d | %s |\n", sev, x.Count, rateStr(&x))
		}
		p("\n")
	}

	p("## Benign quantiles\n\nUpper tail for scores and R_h, lower tail for CV, A_n and spread. Brackets: 95 %% distribution-free interval; `?` = the sample cannot bound that side.\n\n| Metric | n | Tail | 1 − 10⁻² | 1 − 10⁻³ | 1 − 10⁻⁴ |\n|---|---|---|---|---|---|\n")
	for _, k := range sortedKeysOf(r.BenignQuantiles) {
		q := r.BenignQuantiles[k]
		p("| %s | %d | %s | %s | %s | %s |\n", k, q.N, q.Tail, qStr(q, 0), qStr(q, 1), qStr(q, 2))
	}
	p("\n")

	if len(r.TopBenign) > 0 {
		p("## Top %d benign findings\n\n| Score | Severity | Category | Title | Reasons | Capture |\n|---|---|---|---|---|---|\n", len(r.TopBenign))
		for _, f := range r.TopBenign {
			p("| %.2f | %s | %s | %s | %s | %s |\n", f.Score, f.Severity, f.Category, mdEsc(f.Title), mdEsc(strings.Join(f.Reasons, "; ")), f.Capture)
		}
		p("\n")
	}
	if len(r.Prevalence) > 0 {
		p("## Destination prevalence (benign set; reported only, not fed back into scores)\n\nDistinct internal clients per (destination, period bucket). Full table: prevalence.csv.\n\n| Destination | Period | Clients |\n|---|---|---|\n")
		for i, x := range r.Prevalence {
			if i == 25 {
				break
			}
			p("| %s | %s | %d |\n", mdEsc(x.Destination), x.PeriodBucket, x.Clients)
		}
		p("\n")
	}
	return b.String()
}

func sortedKeysOf[V any](m map[string]V) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

func propStr(x *Prop) string {
	if x == nil || x.N == 0 {
		return "—"
	}
	return fmt.Sprintf("%.2f [%.2f, %.2f] (%d/%d)", x.P, x.Lo, x.Hi, x.K, x.N)
}

func propV(m map[string]Prop, k string) string {
	x, ok := m[k]
	if !ok {
		return "—"
	}
	return propStr(&x)
}

func rateStr(x *Rate) string {
	if x == nil {
		return "—"
	}
	return fmt.Sprintf("%.4g [%.4g, %.4g]", x.Rate, x.Lo, x.Hi)
}

func qStr(q Quantiles, i int) string {
	f := func(p *float64) string {
		if p == nil {
			return "?"
		}
		return fmt.Sprintf("%.3f", *p)
	}
	return fmt.Sprintf("%.3f [%s, %s]", q.Q[i], f(q.Lo[i]), f(q.Hi[i]))
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func mdEsc(s string) string { return strings.NewReplacer("|", `\|`, "\n", " ").Replace(s) }
