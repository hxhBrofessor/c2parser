package engine

// VA-0 slice 1: framework-blind evidence policy, closed registry, blind-safe
// output projection, audit ledger and the test/eval-only harness entry points.
// FULL mode is the identity: nothing here runs unless a non-nil FRAMEWORK_BLIND
// policy is injected via EvaluateBlind / AnalyzeFileBlind, which the CLI never
// calls. See docs/design/va0-blind-mode.md.

import (
	_ "embed"
	"encoding/json"
	"strings"

	"c2parser/internal/pcapio"
	"c2parser/internal/stats"
)

//go:embed va0_registry.json
var va0RegistryJSON []byte

// EvidenceMode is exactly FULL or FRAMEWORK_BLIND.
type EvidenceMode int

const (
	FullMode EvidenceMode = iota
	FrameworkBlindMode
)

type va0Class int

const (
	classGeneric va0Class = iota
	classFrameworkSpecific
	classSigmaAttribution
	classDerivedCorrelation
	classMixed
	classUnknown
)

func (c va0Class) String() string {
	switch c {
	case classGeneric:
		return "generic"
	case classFrameworkSpecific:
		return "framework_specific"
	case classSigmaAttribution:
		return "sigma_attribution"
	case classDerivedCorrelation:
		return "derived_correlation"
	case classMixed:
		return "mixed"
	default:
		return "unknown"
	}
}

func parseClass(s string) va0Class {
	switch s {
	case "generic":
		return classGeneric
	case "framework_specific":
		return classFrameworkSpecific
	case "sigma_attribution":
		return classSigmaAttribution
	case "derived_correlation":
		return classDerivedCorrelation
	case "mixed":
		return classMixed
	default:
		return classUnknown
	}
}

type va0Registry struct {
	Version        string                       `json:"version"`
	Exact          map[string]string            `json:"exact"`
	Families       map[string]map[string]string `json:"families"`
	FrameworkNames []string                     `json:"framework_names"`
	NameExclusions []string                     `json:"name_exclusions"`
}

// EvidencePolicy is the injected, immutable blind-mode policy. The zero value
// is never used; construct with newEvidencePolicy.
type EvidencePolicy struct {
	Blind bool
	reg   *va0Registry
}

func newEvidencePolicy(mode EvidenceMode) *EvidencePolicy {
	var reg va0Registry
	if err := json.Unmarshal(va0RegistryJSON, &reg); err != nil {
		panic("va0: bad embedded registry: " + err.Error())
	}
	return &EvidencePolicy{Blind: mode == FrameworkBlindMode, reg: &reg}
}

// classify resolves a signal name by exact name first, then by a registered
// family prefix with a closed suffix allow-list (or a "*" wildcard slot).
// Anything else is classUnknown (fail-closed).
func (p *EvidencePolicy) classify(name string) va0Class {
	if c, ok := p.reg.Exact[name]; ok {
		return parseClass(c)
	}
	for prefix, suffixes := range p.reg.Families {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		suffix := name[len(prefix):]
		if c, ok := suffixes[suffix]; ok {
			return parseClass(c)
		}
		if c, ok := suffixes["*"]; ok {
			return parseClass(c)
		}
		return classUnknown // registered family, unregistered suffix -> block
	}
	return classUnknown
}

// suppresses reports whether a signal is dropped before scoring in BLIND mode:
// framework_specific, sigma_attribution, mixed, and unknown (fail-closed).
// generic is retained; derived_correlation is rederived (retained; the
// correlation passes recompute it over the already-blind accumulators).
func (p *EvidencePolicy) suppresses(name string) bool {
	switch p.classify(name) {
	case classFrameworkSpecific, classSigmaAttribution, classMixed, classUnknown:
		return true
	default:
		return false
	}
}

func (p *EvidencePolicy) frameworkNames() []string { return p.reg.FrameworkNames }

// projectText is the residual safety net (V0-1): any registry framework name
// still present in surviving (generic) text is removed with neutral wording —
// no "[framework]" token, which would itself reveal that a framework was
// recognized. The primary mechanism is dropping evidence/frames of suppressed
// signals (evidenceFrom/framesFrom), so this should rarely fire.
func (p *EvidencePolicy) projectText(s string) string {
	changed := false
	for _, n := range p.reg.FrameworkNames {
		if r := replaceFold(s, n, ""); r != s {
			s, changed = r, true
		}
	}
	if changed {
		s = strings.Join(strings.Fields(s), " ")
	}
	return s
}

func replaceFold(s, old, new string) string {
	if old == "" {
		return s
	}
	var b strings.Builder
	ls, lo := strings.ToLower(s), strings.ToLower(old)
	for {
		i := strings.Index(ls, lo)
		if i < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:i])
		b.WriteString(new)
		s = s[i+len(old):]
		ls = ls[i+len(lo):]
	}
	return b.String()
}

func (p *EvidencePolicy) projectFinding(f *Finding) {
	f.Title = p.projectText(f.Title)
	for i := range f.Evidence {
		f.Evidence[i] = p.projectText(f.Evidence[i])
	}
	for i := range f.Signals {
		f.Signals[i].Detail = p.projectText(f.Signals[i].Detail)
	}
	for i := range f.ServerNames {
		f.ServerNames[i] = p.projectText(f.ServerNames[i])
	}
}

// ---- audit ledger (R5), harness/test only ----

type SuppressedSig struct {
	Name  string `json:"name"`
	Class string `json:"class"`
}

type BlindEntry struct {
	Key           string          `json:"key"`
	Category      string          `json:"category"`
	Suppressed    []SuppressedSig `json:"suppressed,omitempty"`
	FullScore     float64         `json:"full_score"`
	BlindScore    float64         `json:"blind_score"`
	FullSeverity  string          `json:"full_severity"`
	BlindSeverity string          `json:"blind_severity"`
	ExistedFull   bool            `json:"existed_full"`
	SurvivedBlind bool            `json:"survived_blind"`
}

type BlindLedger struct {
	PolicyVersion string       `json:"policy_version"`
	Entries       []BlindEntry `json:"entries"`
}

type BlindResult struct {
	Full   []Finding
	Blind  []Finding
	Ledger *BlindLedger
}

// blindKeyInfo is the per-key collector populated by scoreCore when a non-nil
// collect map is supplied (EvaluateBlind only). It never affects FULL output.
type blindKeyInfo struct {
	category   string
	score      float64
	severity   string
	exists     bool
	suppressed []SuppressedSig
}

// vaSeverity is the production severity for any FULL/BLIND comparison (R0-3).
func vaSeverity(raw float64) string { return stats.Severity(round2(raw)) }

// EvaluateBlind runs the FULL scoring (identical to score()) and a
// FRAMEWORK_BLIND projection over the same engine state, returning both finding
// sets and the audit ledger. Test/eval harness only — never called from
// Finish or the CLI.
func (e *Engine) EvaluateBlind() *BlindResult {
	fullCollect := map[string]*blindKeyInfo{}
	scFull := &scorer{e: e, accs: map[string]*acc{}, collect: fullCollect}
	full := e.scoreCore(scFull)

	pol := newEvidencePolicy(FrameworkBlindMode)
	blindCollect := map[string]*blindKeyInfo{}
	scBlind := &scorer{e: e, accs: map[string]*acc{}, pol: pol, collect: blindCollect}
	blind := e.scoreCore(scBlind)

	led := &BlindLedger{PolicyVersion: pol.reg.Version}
	seen := map[string]bool{}
	add := func(key string) {
		if seen[key] {
			return
		}
		seen[key] = true
		f, fok := fullCollect[key]
		b, bok := blindCollect[key]
		var e BlindEntry
		e.Key = key
		switch {
		case fok:
			e.Category = f.category
		case bok:
			e.Category = b.category
		}
		if fok {
			e.FullScore, e.FullSeverity, e.ExistedFull = f.score, f.severity, f.exists
		}
		if bok {
			e.BlindScore, e.BlindSeverity, e.SurvivedBlind = b.score, b.severity, b.exists
			e.Suppressed = b.suppressed
		}
		led.Entries = append(led.Entries, e)
	}
	for k := range fullCollect {
		add(k)
	}
	for k := range blindCollect {
		add(k)
	}
	return &BlindResult{Full: full, Blind: blind, Ledger: led}
}

// AnalyzeFileBlind parses a capture and returns FULL + BLIND findings and the
// ledger. Test/eval harness only.
func AnalyzeFileBlind(path string, cfg Config) (*BlindResult, error) {
	r, err := pcapio.Open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	eng := New(cfg)
	defer eng.releaseLeanGC()
	if err := eng.Ingest(r); err != nil {
		return nil, err
	}
	return eng.finishBlind(), nil
}

// finishBlind mirrors Finish's flush prelude (production Finish is left
// untouched) and then evaluates both modes from the live engine state.
func (e *Engine) finishBlind() *BlindResult {
	defer e.leanFinish()()
	e.asm.FlushAll()
	for _, c := range e.allTCP {
		e.finishConn(c)
	}
	e.flushUDP()
	return e.EvaluateBlind()
}
