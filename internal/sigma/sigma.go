// Package sigma loads Sigma rules (https://github.com/SigmaHQ/sigma) and
// evaluates them against events c2parser derives from packets. It is a
// faithful implementation of the subset the network rule corpus uses:
//
//   - detection maps (AND of fields), lists of maps (OR), keyword lists
//   - modifiers: contains, startswith, endswith, all, re (+ i/m/s), cidr,
//     base64, base64offset, windash, exists, cased, gt/gte/lt/lte
//   - Sigma wildcards * and ? with backslash escaping, case-insensitive by
//     default, null values
//   - conditions: and / or / not / parentheses / "1 of x*" / "all of x*" /
//     "1 of them" / "all of them"; a list of conditions is OR'd
//
// Aggregations (| count() …), correlation rules, fieldref and expand are
// reported as unsupported rather than silently mis-evaluated.
package sigma

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
)

// Event is one derived log record: field → values.
type Event map[string][]string

// Logsource is the rule's logsource block.
type Logsource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
	Service  string `yaml:"service"`
}

// Rule is a compiled Sigma rule.
type Rule struct {
	ID          string
	Title       string
	Level       string
	Status      string
	Description string
	Tags        []string
	Logsource   Logsource
	Kind        string // which derived event stream it runs on
	File        string
	det         *detection
}

// KindOf maps a logsource to the event stream c2parser can produce for it.
func KindOf(ls Logsource) (string, bool) {
	c, p, s := strings.ToLower(ls.Category), strings.ToLower(ls.Product), strings.ToLower(ls.Service)
	switch {
	case c == "proxy" || c == "webserver":
		return "http", true
	case c == "dns" && (p == "" || p == "zeek"):
		return "dns", true
	case c == "firewall":
		return "conn", true
	case p == "zeek":
		switch s {
		case "http", "dns", "smb_files", "dce_rpc", "x509", "rdp", "conn":
			return s, true
		}
	}
	return "", false
}

// LoadReport summarises a load.
type LoadReport struct {
	Files       int            `json:"files"`
	Loaded      int            `json:"loaded"`
	ByKind      map[string]int `json:"by_kind"`
	Unsupported map[string]int `json:"unsupported"` // reason → count
	Errors      []string       `json:"errors,omitempty"`
}

// Load reads every .yml/.yaml under the given files/directories and keeps
// rules whose logsource c2parser can feed.
func Load(paths ...string) ([]*Rule, LoadReport) {
	var all []*Rule
	rep := newReport()
	for _, root := range paths {
		fi, err := os.Stat(root)
		if err != nil {
			rep.Errors = append(rep.Errors, err.Error())
			continue
		}
		var rs []*Rule
		var r LoadReport
		if fi.IsDir() {
			rs, r = LoadFS(os.DirFS(root), root)
		} else {
			rs, r = LoadFS(os.DirFS(filepath.Dir(root)), filepath.Dir(root), filepath.Base(root))
		}
		all = append(all, rs...)
		rep.merge(r)
	}
	return Dedup(all), rep
}

func newReport() LoadReport {
	return LoadReport{ByKind: map[string]int{}, Unsupported: map[string]int{}}
}

func (r *LoadReport) merge(o LoadReport) {
	r.Files += o.Files
	r.Loaded += o.Loaded
	for k, v := range o.ByKind {
		r.ByKind[k] += v
	}
	for k, v := range o.Unsupported {
		r.Unsupported[k] += v
	}
	r.Errors = append(r.Errors, o.Errors...)
}

// Merge combines reports (e.g. cached SigmaHQ + embedded custom rules).
func (r *LoadReport) Merge(o LoadReport) { r.merge(o) }

// LoadFS loads rules from a filesystem (a directory or an embed.FS). label
// prefixes file names in reports; only, if given, restricts to those files.
func LoadFS(fsys fs.FS, label string, only ...string) ([]*Rule, LoadReport) {
	rep := newReport()
	var rules []*Rule
	fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if len(only) > 0 && p != only[0] {
			return nil
		}
		if ext := strings.ToLower(path.Ext(p)); ext != ".yml" && ext != ".yaml" {
			return nil
		}
		rep.Files++
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			rep.Errors = append(rep.Errors, err.Error())
			return nil
		}
		name := path.Join(label, p)
		r, reason, err := Parse(b, name)
		switch {
		case err != nil:
			rep.Unsupported["error: "+shortErr(err)]++
			if len(rep.Errors) < 50 {
				rep.Errors = append(rep.Errors, fmt.Sprintf("%s: %v", name, err))
			}
		case reason != "":
			rep.Unsupported[reason]++
		default:
			rules = append(rules, r)
			rep.Loaded++
			rep.ByKind[r.Kind]++
		}
		return nil
	})
	sort.Slice(rules, func(i, j int) bool { return rules[i].File < rules[j].File })
	return rules, rep
}

// Dedup drops rules whose ID was already seen (first wins).
func Dedup(rs []*Rule) []*Rule {
	seen := map[string]bool{}
	out := rs[:0]
	for _, r := range rs {
		if r.ID != "" {
			if seen[r.ID] {
				continue
			}
			seen[r.ID] = true
		}
		out = append(out, r)
	}
	return out
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.IndexAny(s, ":\n"); i > 0 {
		s = s[:i]
	}
	return s
}

// Parse compiles one rule. A non-empty reason means "valid but not
// applicable to packet-derived events" (e.g. Windows process creation).
func Parse(b []byte, file string) (*Rule, string, error) {
	if docs := strings.Count("\n"+string(b), "\n---"); docs > 0 && strings.TrimSpace(strings.SplitN(string(b), "\n---", 2)[1]) != "" {
		return nil, "multi-document rule collection", nil
	}
	var raw struct {
		ID          string         `yaml:"id"`
		Title       string         `yaml:"title"`
		Level       string         `yaml:"level"`
		Status      string         `yaml:"status"`
		Description string         `yaml:"description"`
		Tags        []string       `yaml:"tags"`
		Logsource   Logsource      `yaml:"logsource"`
		Detection   map[string]any `yaml:"detection"`
		Correlation map[string]any `yaml:"correlation"`
	}
	if err := safeUnmarshal(b, &raw); err != nil {
		return nil, "", err
	}
	if raw.Correlation != nil {
		return nil, "correlation rule", nil
	}
	if raw.Detection == nil {
		return nil, "no detection block", nil
	}
	switch strings.ToLower(raw.Status) {
	case "deprecated", "unsupported":
		return nil, "status " + strings.ToLower(raw.Status), nil
	}
	kind, ok := KindOf(raw.Logsource)
	if !ok {
		ls := raw.Logsource
		return nil, fmt.Sprintf("logsource %s/%s/%s not derivable from packets", orStar(ls.Product), orStar(ls.Category), orStar(ls.Service)), nil
	}
	det, err := compileDetection(raw.Detection)
	if err != nil {
		return nil, "", err
	}
	return &Rule{ID: raw.ID, Title: raw.Title, Level: strings.ToLower(raw.Level), Status: raw.Status,
		Description: raw.Description, Tags: raw.Tags, Logsource: raw.Logsource, Kind: kind, File: file, det: det}, "", nil
}

func orStar(s string) string {
	if s == "" {
		return "*"
	}
	return s
}

// Match evaluates the rule against one event.
func (r *Rule) Match(ev Event) bool { return r.det.cond.eval(r.det, ev) }

// ------------------------------------------------------------- detection

type detection struct {
	idents map[string]*search
	names  []string
	cond   node
}

// search is one named selection: OR over alternatives; each alternative is
// an AND over field matchers, or a keyword list (OR).
type search struct {
	alts     [][]*fieldMatcher
	keywords []*pattern
}

type fieldMatcher struct {
	field    string
	all      bool
	null     bool
	exists   *bool
	patterns []*pattern
}

func compileDetection(d map[string]any) (*detection, error) {
	det := &detection{idents: map[string]*search{}}
	var conds []string
	for k, v := range d {
		switch k {
		case "condition":
			switch c := v.(type) {
			case string:
				conds = append(conds, c)
			case []any:
				for _, x := range c {
					conds = append(conds, fmt.Sprint(x))
				}
			}
			continue
		case "timeframe":
			return nil, errors.New("timeframe (aggregation) unsupported")
		}
		s, err := compileSearch(v)
		if err != nil {
			return nil, fmt.Errorf("selection %s: %w", k, err)
		}
		det.idents[k] = s
		det.names = append(det.names, k)
	}
	sort.Strings(det.names)
	if len(conds) == 0 {
		return nil, errors.New("missing condition")
	}
	var nodes []node
	for _, c := range conds {
		if strings.Contains(c, "|") {
			return nil, errors.New("aggregation in condition unsupported")
		}
		n, err := parseCondition(c, det)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	if len(nodes) == 1 {
		det.cond = nodes[0]
	} else {
		det.cond = &orNode{nodes}
	}
	return det, nil
}

func compileSearch(v any) (*search, error) {
	s := &search{}
	switch x := v.(type) {
	case map[string]any:
		fm, err := compileMap(x)
		if err != nil {
			return nil, err
		}
		s.alts = append(s.alts, fm)
	case []any:
		for _, item := range x {
			if m, ok := item.(map[string]any); ok {
				fm, err := compileMap(m)
				if err != nil {
					return nil, err
				}
				s.alts = append(s.alts, fm)
			} else {
				p, err := compilePattern(scalar(item), []string{"contains"})
				if err != nil {
					return nil, err
				}
				s.keywords = append(s.keywords, p)
			}
		}
	default:
		p, err := compilePattern(scalar(x), []string{"contains"})
		if err != nil {
			return nil, err
		}
		s.keywords = append(s.keywords, p)
	}
	return s, nil
}

func scalar(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case uint64:
		return strconv.FormatUint(x, 10)
	case int64:
		return strconv.FormatInt(x, 10)
	case int:
		return strconv.Itoa(x)
	}
	return fmt.Sprint(v)
}

func compileMap(m map[string]any) ([]*fieldMatcher, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []*fieldMatcher
	for _, k := range keys {
		parts := strings.Split(k, "|")
		fm := &fieldMatcher{field: parts[0]}
		var mods []string
		for _, mod := range parts[1:] {
			switch mod = strings.ToLower(mod); mod {
			case "all":
				fm.all = true
			case "exists":
				fm.exists = new(bool)
			case "fieldref", "expand", "utf16le", "utf16be", "utf16", "wide":
				return nil, fmt.Errorf("modifier %q unsupported", mod)
			default:
				mods = append(mods, mod)
			}
		}
		vals := []any{m[k]}
		if l, ok := m[k].([]any); ok {
			vals = l
		}
		for _, v := range vals {
			if fm.exists != nil {
				b, _ := v.(bool)
				*fm.exists = b
				continue
			}
			if v == nil {
				fm.null = true
				continue
			}
			p, err := compilePattern(scalar(v), mods)
			if err != nil {
				return nil, err
			}
			fm.patterns = append(fm.patterns, p)
		}
		out = append(out, fm)
	}
	return out, nil
}

// ---------------------------------------------------------------- values

type pattern struct {
	re    *regexp.Regexp
	cidr  []netip.Prefix
	num   func(float64) bool
	plain []string // lower-cased literal alternatives for the fast path
	mode  int      // fast-path mode
	cased bool
}

const (
	modeRegex = iota
	modeEq
	modeContains
	modePrefix
	modeSuffix
)

func compilePattern(v string, mods []string) (*pattern, error) {
	p := &pattern{}
	pos := ""
	var b64, b64off, windash, isRe bool
	reFlags := ""
	for _, m := range mods {
		switch m {
		case "contains", "startswith", "endswith":
			pos = m
		case "base64":
			b64 = true
		case "base64offset":
			b64off = true
		case "windash":
			windash = true
		case "re":
			isRe = true
		case "i", "m", "s":
			reFlags += m
		case "cased":
			p.cased = true
		case "cidr":
			pr, err := netip.ParsePrefix(v)
			if err != nil {
				return nil, fmt.Errorf("bad cidr %q", v)
			}
			p.cidr = append(p.cidr, pr.Masked())
			return p, nil
		case "gt", "gte", "lt", "lte":
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return nil, fmt.Errorf("bad number %q", v)
			}
			switch m {
			case "gt":
				p.num = func(x float64) bool { return x > f }
			case "gte":
				p.num = func(x float64) bool { return x >= f }
			case "lt":
				p.num = func(x float64) bool { return x < f }
			default:
				p.num = func(x float64) bool { return x <= f }
			}
			return p, nil
		default:
			return nil, fmt.Errorf("modifier %q unsupported", m)
		}
	}
	if isRe {
		expr := v
		if reFlags != "" {
			expr = "(?" + reFlags + ")" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("regex not RE2-compatible: %v", err)
		}
		p.re, p.mode = re, modeRegex
		return p, nil
	}
	// Expand value transforms into literal alternatives (wildcards in
	// encoded values are not meaningful, so they are taken literally).
	alts := []string{v}
	switch {
	case b64:
		alts = []string{base64.StdEncoding.EncodeToString([]byte(unescape(v)))}
	case b64off:
		alts = base64Offsets(unescape(v))
		if pos == "" {
			pos = "contains"
		}
	case windash:
		alts = nil
		for _, d := range []string{"-", "/", "–", "—", "―"} {
			alts = append(alts, strings.ReplaceAll(v, "-", d))
		}
	}
	// Fast path when there are no wildcards in any alternative.
	simple := true
	for _, a := range alts {
		if hasWildcard(a) {
			simple = false
		}
	}
	if simple && (b64 || b64off || !strings.ContainsRune(v, '\\') || !needsUnescape(v)) {
		for _, a := range alts {
			if !b64 && !b64off {
				a = unescape(a)
			}
			if !p.cased {
				a = strings.ToLower(a)
			}
			p.plain = append(p.plain, a)
		}
		switch pos {
		case "contains":
			p.mode = modeContains
		case "startswith":
			p.mode = modePrefix
		case "endswith":
			p.mode = modeSuffix
		default:
			p.mode = modeEq
		}
		return p, nil
	}
	var parts []string
	for _, a := range alts {
		r := globToRegex(a)
		switch pos {
		case "contains":
			r = ".*" + r + ".*"
		case "startswith":
			r = r + ".*"
		case "endswith":
			r = ".*" + r
		}
		parts = append(parts, r)
	}
	flags := "(?s)"
	if !p.cased {
		flags = "(?is)"
	}
	re, err := regexp.Compile(flags + "^(?:" + strings.Join(parts, "|") + ")$")
	if err != nil {
		return nil, err
	}
	p.re, p.mode = re, modeRegex
	return p, nil
}

// Sigma string syntax: * and ? are wildcards; a backslash escapes *, ? or
// a backslash; any other backslash is literal.
func hasWildcard(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '?' || s[i+1] == '\\') {
				i++
			}
		case '*', '?':
			return true
		}
	}
	return false
}

func needsUnescape(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '\\' && (s[i+1] == '*' || s[i+1] == '?' || s[i+1] == '\\') {
			return true
		}
	}
	return false
}

func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '?' || s[i+1] == '\\') {
			b.WriteByte(s[i+1])
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func globToRegex(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '?' || s[i+1] == '\\'):
			b.WriteString(regexp.QuoteMeta(string(s[i+1])))
			i++
		case c == '*':
			b.WriteString(".*")
		case c == '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}

// base64Offsets returns the three base64 renderings of v at byte offsets
// 0/1/2, trimmed to the stable middle part (Sigma's base64offset).
func base64Offsets(v string) []string {
	start := []int{0, 2, 3}
	end := []int{0, 3, 2}
	var out []string
	for i := 0; i < 3; i++ {
		enc := base64.StdEncoding.EncodeToString(append(make([]byte, i), v...))
		e := (len(v) + i) % 3
		s, t := start[i], len(enc)-end[e]
		if e == 0 {
			t = len(enc)
		}
		if s < t {
			out = append(out, enc[s:t])
		}
	}
	return out
}

func (p *pattern) match(v string) bool {
	switch {
	case p.cidr != nil:
		a, err := netip.ParseAddr(v)
		if err != nil {
			return false
		}
		for _, c := range p.cidr {
			if c.Contains(a.Unmap()) {
				return true
			}
		}
		return false
	case p.num != nil:
		f, err := strconv.ParseFloat(v, 64)
		return err == nil && p.num(f)
	case p.mode == modeRegex:
		return p.re.MatchString(v)
	}
	if !p.cased {
		v = strings.ToLower(v)
	}
	for _, a := range p.plain {
		switch p.mode {
		case modeEq:
			if v == a {
				return true
			}
		case modeContains:
			if strings.Contains(v, a) {
				return true
			}
		case modePrefix:
			if strings.HasPrefix(v, a) {
				return true
			}
		case modeSuffix:
			if strings.HasSuffix(v, a) {
				return true
			}
		}
	}
	return false
}

func lookup(ev Event, field string) ([]string, bool) {
	if v, ok := ev[field]; ok {
		return v, true
	}
	for k, v := range ev {
		if strings.EqualFold(k, field) {
			return v, true
		}
	}
	return nil, false
}

func (fm *fieldMatcher) match(ev Event) bool {
	vals, ok := lookup(ev, fm.field)
	if fm.exists != nil {
		return ok == *fm.exists
	}
	nonEmpty := false
	for _, v := range vals {
		if v != "" {
			nonEmpty = true
		}
	}
	if fm.null && !nonEmpty {
		return true
	}
	if len(fm.patterns) == 0 {
		return false
	}
	if fm.all {
		for _, p := range fm.patterns {
			hit := false
			for _, v := range vals {
				if p.match(v) {
					hit = true
					break
				}
			}
			if !hit {
				return false
			}
		}
		return true
	}
	for _, p := range fm.patterns {
		for _, v := range vals {
			if p.match(v) {
				return true
			}
		}
	}
	return false
}

func (s *search) match(ev Event) bool {
	for _, alt := range s.alts {
		ok := true
		for _, fm := range alt {
			if !fm.match(ev) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	for _, k := range s.keywords {
		for _, vals := range ev {
			for _, v := range vals {
				if k.match(v) {
					return true
				}
			}
		}
	}
	return false
}

// ------------------------------------------------------------- condition

type node interface {
	eval(d *detection, ev Event) bool
}

type identNode struct{ name string }
type notNode struct{ n node }
type andNode struct{ ns []node }
type orNode struct{ ns []node }
type quantNode struct {
	all     bool
	pattern string // glob over selection names, "them" = all
}

func (n *identNode) eval(d *detection, ev Event) bool {
	s := d.idents[n.name]
	return s != nil && s.match(ev)
}
func (n *notNode) eval(d *detection, ev Event) bool { return !n.n.eval(d, ev) }
func (n *andNode) eval(d *detection, ev Event) bool {
	for _, x := range n.ns {
		if !x.eval(d, ev) {
			return false
		}
	}
	return true
}
func (n *orNode) eval(d *detection, ev Event) bool {
	for _, x := range n.ns {
		if x.eval(d, ev) {
			return true
		}
	}
	return false
}
func (n *quantNode) eval(d *detection, ev Event) bool {
	matched := 0
	total := 0
	for _, name := range d.names {
		if n.pattern == "them" {
			if strings.HasPrefix(name, "_") {
				continue
			}
		} else if ok, _ := filepath.Match(n.pattern, name); !ok {
			continue
		}
		total++
		if d.idents[name].match(ev) {
			matched++
			if !n.all {
				return true
			}
		} else if n.all {
			return false
		}
	}
	return n.all && total > 0 && matched == total
}

type condParser struct {
	toks []string
	i    int
	det  *detection
}

func tokenize(s string) []string {
	var out []string
	cur := strings.Builder{}
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch r {
		case '(', ')':
			flush()
			out = append(out, string(r))
		case ' ', '\t', '\n':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

func parseCondition(s string, det *detection) (node, error) {
	p := &condParser{toks: tokenize(s), det: det}
	n, err := p.expr()
	if err != nil {
		return nil, fmt.Errorf("condition %q: %w", s, err)
	}
	if p.i != len(p.toks) {
		return nil, fmt.Errorf("condition %q: unexpected %q", s, p.toks[p.i])
	}
	return n, nil
}

func (p *condParser) peek() string {
	if p.i < len(p.toks) {
		return strings.ToLower(p.toks[p.i])
	}
	return ""
}

func (p *condParser) expr() (node, error) {
	l, err := p.term()
	if err != nil {
		return nil, err
	}
	ns := []node{l}
	for p.peek() == "or" {
		p.i++
		r, err := p.term()
		if err != nil {
			return nil, err
		}
		ns = append(ns, r)
	}
	if len(ns) == 1 {
		return l, nil
	}
	return &orNode{ns}, nil
}

func (p *condParser) term() (node, error) {
	l, err := p.factor()
	if err != nil {
		return nil, err
	}
	ns := []node{l}
	for p.peek() == "and" {
		p.i++
		r, err := p.factor()
		if err != nil {
			return nil, err
		}
		ns = append(ns, r)
	}
	if len(ns) == 1 {
		return l, nil
	}
	return &andNode{ns}, nil
}

func (p *condParser) factor() (node, error) {
	switch t := p.peek(); {
	case t == "":
		return nil, errors.New("unexpected end")
	case t == "not":
		p.i++
		n, err := p.factor()
		if err != nil {
			return nil, err
		}
		return &notNode{n}, nil
	case t == "(":
		p.i++
		n, err := p.expr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, errors.New("missing )")
		}
		p.i++
		return n, nil
	case t == "1" || t == "all" || t == "any":
		if p.i+2 >= len(p.toks) {
			return nil, errors.New("incomplete quantifier")
		}
		if strings.ToLower(p.toks[p.i+1]) != "of" {
			return nil, fmt.Errorf("expected 'of' after %q", t)
		}
		pat := p.toks[p.i+2]
		p.i += 3
		return &quantNode{all: t == "all", pattern: pat}, nil
	default:
		name := p.toks[p.i]
		p.i++
		if _, ok := p.det.idents[name]; !ok {
			return nil, fmt.Errorf("unknown selection %q", name)
		}
		return &identNode{name}, nil
	}
}

// safeUnmarshal is yaml.Unmarshal that turns a decoder panic into an
// error (goccy/go-yaml v1.19.2 panics on some malformed input, e.g. a
// tagged mapping where a sequence is expected; found by fuzzing).
func safeUnmarshal(b []byte, v any, opts ...yaml.DecodeOption) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("yaml: malformed input (%v)", r)
		}
	}()
	return yaml.UnmarshalWithOptions(b, v, opts...)
}
