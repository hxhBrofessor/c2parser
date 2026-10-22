// c2parser hunts for command-and-control and exfiltration in packet
// captures: HTTP C2, SMB named-pipe pivots, DNS tunnelling/DGA, and
// upload-heavy transfers. Every finding carries the signals that produced
// its score, so results can be explained and tuned.
//
//	c2parser [flags] capture.pcapng [more.pcap ...]
package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	iofs "io/fs"

	"c2parser/internal/engine"
	"c2parser/internal/eval"
	"c2parser/internal/report"
	"c2parser/internal/sigma"
	"c2parser/internal/stats"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	// every run starts with the banner (stderr, interactive terminals only)
	printBanner(os.Stderr, isTerminal(os.Stderr), bannerOff(args))
	if len(args) > 0 && args[0] == "eval" {
		return runEval(args[1:])
	}
	fs := flag.NewFlagSet("c2parser", flag.ContinueOnError)
	var (
		asJSON        = fs.Bool("json", false, "emit JSON instead of the text report")
		candidateJSON = fs.String("candidate-json", "", "write bounded, unconfirmed Base32/Base58 candidates to a separate JSON file")
		verbose       = fs.Bool("v", false, "verbose: include per-protocol tables and weak signals")
		minScore      = fs.Float64("min-score", 0.2, "hide findings scoring below this (0..1)")
		internal      = fs.String("internal", strings.Join(engine.DefaultInternal, ","), "comma-separated CIDRs treated as internal")
		addInt        = fs.String("add-internal", "", "extra internal CIDRs appended to -internal (e.g. 100.64.0.0/10 for Tailscale)")
		legacy        = fs.Float64("entropy", 7.80, "legacy raw Shannon threshold reported alongside the new randomness score")
		exfilHalf     = fs.String("exfil-bytes", "1MB", "upload volume that earns half credit in the exfil score")
		exfilMin      = fs.String("exfil-min", "256KB", "ignore channels uploading less than this")
		burstGap      = fs.Duration("burst-gap", 250*time.Millisecond, "client silence that ends one beacon burst")
		minBeacon     = fs.Int("min-beacon", 8, "minimum events before timing is scored")
		dnsAllow      = fs.String("dns-allow", "", "comma-separated domains to exclude from DNS tunnel scoring")
		allPairs      = fs.Bool("all-pairs", false, "also score internal↔internal pairs for beaconing/exfil")
		failOn        = fs.String("fail-on", "", "exit 2 if any finding reaches this severity (low|medium|high|critical)")
		sigmaDirs     = fs.String("sigma", "", "extra Sigma rule files/directories (comma-separated), added to the auto-updated SigmaHQ set")
		sigmaList     = fs.Bool("sigma-report", false, "print which Sigma rules loaded/skipped and why, then continue")
		noSigma       = fs.Bool("no-sigma", false, "disable Sigma rules entirely")
		noAuto        = fs.Bool("no-sigma-update", false, "don't auto-update SigmaHQ rules (use the cache and built-in rules)")
		updSigma      = fs.Bool("update-sigma", false, "check SigmaHQ for new rules now (like nuclei -ut); with no captures, update and exit")
		offline       = fs.Bool("offline", false, "never touch the network; use cached + built-in rules")
		sigRef        = fs.String("sigma-ref", "", "pin SigmaHQ to a branch, tag or commit SHA (default: latest default branch)")
		sigRepo       = fs.String("sigma-repo", "SigmaHQ/sigma", "GitHub owner/repo to pull Sigma rules from (e.g. your fork)")
		sigCache      = fs.String("sigma-cache", "", "Sigma cache directory (default: user cache dir/c2parser/sigma)")
		sigMaxAge     = fs.Duration("sigma-max-age", 24*time.Hour, "how often the auto-update checks GitHub")
		timing        = fs.String("timing", "v1", "timing/scoring engine: v1 (default, v6 behaviour) or v2 (v8: event models, refusal ladder, null-calibrated dispersion, name-keyed series, signal families)")
		showVer       = fs.Bool("version", false, "print the version and exit")
		jobs          = fs.Int("j", 1, "analyse up to N capture files concurrently (memory ≈ N × per-file peak); output stays in argument order")
		maxEvents     = fs.Int("max-series-events", 200000, "cap on stored events per timing series (dropped events are counted in series_events_dropped)")
		maxRows       = fs.Int("max-summary-rows", 5000, "cap on rows per summary table (http_channels, dns_domains); findings are unaffected")
		leanGC        = fs.Int("lean-gc-mb", 512, "above this live heap (MB), collect garbage more often to cut peak memory (0 = off)")
		dcList        = fs.String("dc", "", "comma-separated domain controller IPs (added to those inferred from Kerberos/LDAP service and drsuapi): their replication is not DCSync and their LDAP/samr is not recon")
		_             = fs.Bool("no-banner", false, "don't print the startup banner (it only shows on an interactive terminal; also C2PARSER_NO_BANNER=1)")
		iocFile       = fs.String("ioc", "", "file of indicators, one per line: ip:, domain:, ja3:, ja3s:, ja4:, cert: (sha256) — or bare values; '#' starts a label")
	)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: c2parser [flags] <capture.pcap|.pcapng> [...]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 64
	}
	if *showVer {
		fmt.Println("c2parser", version)
		return 0
	}
	if fs.NArg() == 0 && !*updSigma {
		fs.Usage()
		return 64
	}
	var candidateProtected []os.FileInfo
	if *candidateJSON != "" {
		protectedPaths := append([]string(nil), fs.Args()...)
		if *iocFile != "" {
			protectedPaths = append(protectedPaths, *iocFile)
		}
		if *sigmaDirs != "" {
			protectedPaths = append(protectedPaths, strings.Split(*sigmaDirs, ",")...)
		}
		if !*noSigma {
			cache := *sigCache
			if cache == "" {
				base, err := os.UserCacheDir()
				if err != nil {
					fmt.Fprintln(os.Stderr, "error: candidate JSON destination safety: cannot resolve Sigma cache:", err)
					return 64
				}
				cache = filepath.Join(base, "c2parser", "sigma")
			}
			if _, err := os.Stat(cache); err == nil {
				protectedPaths = append(protectedPaths, cache)
			} else if !os.IsNotExist(err) {
				fmt.Fprintln(os.Stderr, "error: candidate JSON destination safety: cannot inspect Sigma cache:", err)
				return 64
			}
		}
		var err error
		candidateProtected, err = candidateProtectedFiles(protectedPaths, os.Stdout, os.Stderr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: candidate JSON destination safety:", err)
			return 64
		}
		destination, err := openCandidateDestination(*candidateJSON, candidateProtected)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: candidate JSON destination safety:", err)
			return 64
		}
		destination.close()
	}
	if *timing != "v1" && *timing != "v2" {
		fmt.Fprintln(os.Stderr, "error: -timing must be v1 or v2")
		return 64
	}
	cidrs := strings.Split(*internal, ",")
	if *addInt != "" {
		cidrs = append(cidrs, strings.Split(*addInt, ",")...)
	}
	prefixes, err := engine.ParsePrefixes(cidrs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 64
	}
	half, err1 := parseSize(*exfilHalf)
	minB, err2 := parseSize(*exfilMin)
	if err1 != nil || err2 != nil {
		fmt.Fprintln(os.Stderr, "error: bad size for -exfil-bytes / -exfil-min")
		return 64
	}
	var allow []string
	for _, d := range strings.Split(*dnsAllow, ",") {
		if d = strings.TrimSpace(d); d != "" {
			allow = append(allow, d)
		}
	}
	var iocs []engine.IOC
	if *iocFile != "" {
		b, err := os.ReadFile(*iocFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 64
		}
		for _, l := range strings.Split(string(b), "\n") {
			if i, ok := engine.ParseIOCLine(l); ok {
				iocs = append(iocs, i)
			}
		}
	}
	var rules []*sigma.Rule
	if !*noSigma {
		var rep sigma.LoadReport
		rules, rep = loadSigma(sigmaSetup{
			extra: *sigmaDirs, auto: !*noAuto || *updSigma, force: *updSigma, offline: *offline,
			ref: *sigRef, repo: *sigRepo, cache: *sigCache, maxAge: *sigMaxAge,
		})
		if fs.NArg() == 0 { // -update-sigma with nothing to analyse
			return 0
		}
		if *sigmaList {
			reasons := make([]string, 0, len(rep.Unsupported))
			for r, n := range rep.Unsupported {
				reasons = append(reasons, fmt.Sprintf("  %5d  %s", n, r))
			}
			sort.Strings(reasons)
			fmt.Fprintln(os.Stderr, "sigma: skipped:\n"+strings.Join(reasons, "\n"))
			for _, e := range rep.Errors {
				fmt.Fprintln(os.Stderr, "sigma: error:", e)
			}
		}
	}
	cfg := engine.Config{
		Sigma:    rules,
		IOCs:     iocs,
		Internal: prefixes, LegacyEntropy: *legacy, ExfilHalfBytes: half, ExfilMinBytes: minB,
		BurstGap: *burstGap, DNSAllow: allow, AllPairs: *allPairs,
		Beacon:   stats.BeaconParams{MinEvents: *minBeacon, FullEvents: *minBeacon * 5},
		TimingV2: *timing == "v2",
	}

	for _, d := range strings.Split(*dcList, ",") {
		if d = strings.TrimSpace(d); d == "" {
			continue
		}
		a, err := netip.ParseAddr(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: -dc %q: %v\n", d, err)
			return 64
		}
		cfg.DCs = append(cfg.DCs, a.Unmap())
	}
	cfg.MaxChannelEvts, cfg.MaxSummaryRows = *maxEvents, *maxRows
	engine.LeanGCBytes = uint64(*leanGC) << 20

	var results []*engine.Result
	var candidateReports []engine.DecodeCandidateReport
	status := 0
	var files []fileResult
	if *candidateJSON != "" {
		files = analyzeAllWithCandidates(fs.Args(), cfg, *jobs)
	} else {
		files = analyzeAll(fs.Args(), cfg, *jobs)
	}
	for _, r := range files {
		if r.err != nil {
			fmt.Fprintln(os.Stderr, "error:", r.err)
			status = 1
			continue
		}
		results = append(results, r.res)
		if *candidateJSON != "" {
			candidateReports = append(candidateReports, r.candidates)
		}
	}
	opts := report.Options{MinScore: *minScore, Verbose: *verbose}
	if *asJSON {
		if err := report.JSON(os.Stdout, results, opts); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	} else {
		for _, r := range results {
			report.Text(os.Stdout, r, opts)
		}
	}
	if *candidateJSON != "" {
		if status != 0 {
			fmt.Fprintln(os.Stderr, "error: candidate JSON not published because one or more input analyses failed")
			return status
		}
		if err := writeCandidateSidecar(*candidateJSON, candidateProtected, candidateReports); err != nil {
			fmt.Fprintln(os.Stderr, "error: candidate JSON:", err)
			return 1
		}
	}
	if *failOn != "" && stats.SeverityRank(report.MaxSeverity(results, *minScore)) >= stats.SeverityRank(strings.ToLower(*failOn)) {
		return 2
	}
	return status
}

func parseSize(s string) (int64, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	mult := int64(1)
	for _, u := range []struct {
		suf string
		m   int64
	}{{"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(s, u.suf) {
			s, mult = strings.TrimSuffix(s, u.suf), u.m
			break
		}
	}
	var f float64
	if _, err := fmt.Sscanf(s, "%g", &f); err != nil {
		return 0, err
	}
	return int64(f * float64(mult)), nil
}

//go:embed rules/sigma/*.yml
var builtinRules embed.FS

type sigmaSetup struct {
	extra                string
	auto, force, offline bool
	ref, repo, cache     string
	maxAge               time.Duration
}

// loadSigma assembles the rule set: auto-updated SigmaHQ corpus (cached,
// checked at most every maxAge), built-in c2parser rules, and any extra
// paths. Network problems never stop an analysis; they fall back to the
// cache or to built-in rules with a warning.
func loadSigma(c sigmaSetup) ([]*sigma.Rule, sigma.LoadReport) {
	var all []*sigma.Rule
	rep := sigma.LoadReport{ByKind: map[string]int{}, Unsupported: map[string]int{}}
	var parts []string

	if c.auto || c.offline {
		res, err := sigma.Update(context.Background(), sigma.UpdateOptions{
			CacheDir: c.cache, Repo: c.repo, Ref: c.ref, MaxAge: c.maxAge, Force: c.force,
			Offline: c.offline || !c.auto, Log: os.Stderr,
		})
		switch {
		case err != nil:
			fmt.Fprintf(os.Stderr, "sigma: %v — continuing with built-in rules\n", err)
		default:
			fmt.Fprintf(os.Stderr, "sigma: %s\n", res.Note)
			rs, r := sigma.Load(res.State.Dir)
			all = append(all, rs...)
			rep.Merge(r)
			parts = append(parts, fmt.Sprintf("%d %s@%s", len(rs), res.State.Repo, shortSHA(res.State.SHA)))
		}
	}
	sub, _ := fsSub(builtinRules, "rules/sigma")
	rs, r := sigma.LoadFS(sub, "builtin")
	all = append(all, rs...)
	rep.Merge(r)
	parts = append(parts, fmt.Sprintf("%d built-in", len(rs)))
	if c.extra != "" {
		rs, r := sigma.Load(strings.Split(c.extra, ",")...)
		all = append(all, rs...)
		rep.Merge(r)
		parts = append(parts, fmt.Sprintf("%d from -sigma", len(rs)))
	}
	all = sigma.Dedup(all)
	fmt.Fprintf(os.Stderr, "sigma: %d rules active (%s) — %s\n", len(all), strings.Join(parts, " + "), kindSummary(rep.ByKind))
	return all, rep
}

func shortSHA(s string) string {
	if len(s) > 10 {
		return s[:10]
	}
	return s
}

func kindSummary(m map[string]int) string {
	var parts []string
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("%s %d", k, v))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func fsSub(f embed.FS, dir string) (iofs.FS, error) { return iofs.Sub(f, dir) }

// runEval is "c2parser eval": the evaluation harness (see internal/eval).
func runEval(args []string) int {
	fs := flag.NewFlagSet("c2parser eval", flag.ContinueOnError)
	manifest := fs.String("manifest", "", "YAML manifest of captures (schema: docs/eval-manifest.example.yaml)")
	out := fs.String("out", "eval-out", "directory for report.md, report.json, series.csv, detection_vs_jitter.csv, prevalence.csv")
	internal := fs.String("internal", strings.Join(engine.DefaultInternal, ","), "comma-separated CIDRs treated as internal (a manifest's internal: overrides)")
	allPairs := fs.Bool("all-pairs", false, "also score internal↔internal pairs")
	jobs := fs.Int("j", 1, "run up to N captures (or rotated capture sets) concurrently; memory ≈ N × per-capture peak")
	fs.Bool("no-banner", false, "don't print the startup banner")
	calibrate := fs.Bool("calibrate", false, "also fit the calibration harness (nested leave-one-framework-out; writes proposed-weights.json and calibration.md — never changes product weights)")
	check := fs.Bool("check", false, "validate the manifest and that every file exists, then exit")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: c2parser eval -manifest m.yaml [-out dir] [-j N] [-calibrate]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil || *manifest == "" {
		fs.Usage()
		return 64
	}
	m, err := eval.LoadManifest(*manifest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if *check {
		units, err := m.Resolve()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Printf("eval: manifest OK, %d captures → %d runs\n", len(m.Captures), len(units))
		return 0
	}
	prefixes, err := engine.ParsePrefixes(strings.Split(*internal, ","))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 64
	}
	rep, err := eval.RunWith(m, engine.Config{Internal: prefixes, AllPairs: *allPairs}, eval.Options{Jobs: *jobs, Progress: os.Stderr})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if err := rep.Write(*out); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("eval: %d series (%d C2, %d benign) → %s/report.md\n", len(rep.Series), rep.C2Series, rep.BenignSeries, *out)
	if rep.Banner != "" {
		fmt.Println(rep.Banner)
	}
	if rep.Refusal != "" {
		fmt.Println(rep.Refusal)
	}
	for _, n := range rep.Notes {
		fmt.Println("note:", n)
	}
	if *calibrate {
		cal, err := eval.CalibrateReport(rep, eval.CalOptions{})
		if err != nil {
			fmt.Println("calibration: not fitted:", err)
			return 0
		}
		if err := cal.Write(*out); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Printf("calibration: proposed weights → %s/proposed-weights.json (not applied)\n", *out)
	}
	return 0
}

// version is the release tag.
const version = "11.1"

type fileResult struct {
	res        *engine.Result
	candidates engine.DecodeCandidateReport
	err        error
}

// analyzeAll analyses captures with up to jobs workers (v9c 3.1). Each file
// is independent; results come back in argument order, identical to a
// sequential run. Memory is roughly jobs × the largest per-file peak.
func analyzeAll(paths []string, cfg engine.Config, jobs int) []fileResult {
	return analyzeAllMode(paths, cfg, jobs, false)
}

func analyzeAllWithCandidates(paths []string, cfg engine.Config, jobs int) []fileResult {
	return analyzeAllMode(paths, cfg, jobs, true)
}

func analyzeAllMode(paths []string, cfg engine.Config, jobs int, includeCandidates bool) []fileResult {
	out := make([]fileResult, len(paths))
	if jobs < 1 {
		jobs = 1
	}
	if jobs > len(paths) {
		jobs = len(paths)
	}
	next := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < jobs; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				var res *engine.Result
				var candidates engine.DecodeCandidateReport
				var err error
				if includeCandidates {
					res, candidates, err = engine.AnalyzeFileWithCandidates(paths[i], cfg)
				} else {
					res, err = engine.AnalyzeFile(paths[i], cfg)
				}
				out[i] = fileResult{res: res, candidates: candidates, err: err}
			}
		}()
	}
	for i := range paths {
		next <- i
	}
	close(next)
	wg.Wait()
	return out
}
