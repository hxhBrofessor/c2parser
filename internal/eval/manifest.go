package eval

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

// Manifest schema (v10a 1.1). Version 2 is the current schema; a manifest
// with no `version` is the v8/v9 layout (benign: true / c2: endpoints) and
// is read as version 1, then normalised to the same in-memory form.
// Decoding is strict: an unknown key anywhere is an error. Paths resolve
// against the manifest's directory; globs are allowed. Files are checked
// when a run resolves the manifest (Resolve), so a manifest can be
// validated on a machine that does not hold the data.
//
//	version: 2
//	name: tqh-c2 first tranche
//	internal: [10.0.0.0/8]                 # optional; overrides -internal
//	columns: {uid: uid, label: label}       # optional default Zeek column map
//	captures:
//	  - path: tqh/C_mythic_http/*/*.pcap    # glob
//	    role: c2                            # c2 | benign | mixed
//	    framework: mythic
//	    transport: http
//	    labels:
//	      source: zeek-uid                  # none | zeek-uid | per-capture | time-window
//	      conn_log: tqh/C_mythic_http/*/conn.log*
//	      label_file: tqh/labels/labeled.jsonl
//	      positive: [c2]
//	  - path: benign/host-*.pcap
//	    role: benign
//	    rotated: true                       # the matches are one capture split by size
//	    expected_host_hours: 216
const ManifestVersion = 2

// Roles.
const (
	RoleC2     = "c2"     // labelled series are positives; the rest is unverified background
	RoleBenign = "benign" // every series is a negative
	RoleMixed  = "mixed"  // labelled series are positives; the rest are negatives
)

// Label sources.
const (
	LabelNone       = "none"
	LabelZeekUID    = "zeek-uid"
	LabelPerCapture = "per-capture"
	LabelTimeWindow = "time-window"
)

// Manifest lists captures to evaluate.
type Manifest struct {
	Version   int       `yaml:"version"`
	Name      string    `yaml:"name"`
	Synthetic bool      `yaml:"synthetic"` // every capture is generated (synthgen): banner + refusal rule
	Internal  []string  `yaml:"internal"`  // CIDRs; overrides -internal for every capture
	Columns   *Columns  `yaml:"columns"`   // default column map for zeek-uid joins
	Captures  []Capture `yaml:"captures"`

	dir      string
	internal []netip.Prefix
}

// Capture is one capture entry (one file, a glob of separate files, or a
// glob of rotated segments of one capture).
type Capture struct {
	Path      string  `yaml:"path"`
	Rotated   bool    `yaml:"rotated"` // glob matches are one capture split by rotation; ingested in name order into one engine
	Role      string  `yaml:"role"`
	Synthetic bool    `yaml:"synthetic"`
	Licence   string  `yaml:"licence"`   // ccby | internal | own
	Framework string  `yaml:"framework"` // "" for benign captures
	Transport string  `yaml:"transport"`
	Sleep     float64 `yaml:"sleep"`
	Jitter    float64 `yaml:"jitter"` // percent
	Polarity  string  `yaml:"polarity"`
	Tasking   string  `yaml:"tasking"` // yes | no | unknown
	Labels    *Labels `yaml:"labels"`
	// Internal overrides the manifest-level and CLI internal CIDRs.
	Internal []string `yaml:"internal"`
	// ExpectedHostHours (benign only): the report flags a measured figure
	// more than 10 % away (a missing rotation segment, a dead sensor).
	ExpectedHostHours float64 `yaml:"expected_host_hours"`

	// v1 layout (normalised into Role / Labels).
	Benign           bool       `yaml:"benign"`
	C2               []Endpoint `yaml:"c2"`
	BackgroundBenign bool       `yaml:"background_benign"`

	// synthgen provenance (recorded, not used).
	Scenario string   `yaml:"scenario"`
	Seed     uint64   `yaml:"seed"`
	Shapes   []string `yaml:"shapes"`
	SHA256   string   `yaml:"sha256"`

	internal []netip.Prefix
	windows  []window
}

// Labels says where a capture's positive labels come from.
type Labels struct {
	Source string `yaml:"source"`
	// zeek-uid: Zeek conn.log file(s) (glob; TSV or JSON, plain or gzip),
	// and optionally a separate label file (JSON lines, Zeek TSV or CSV)
	// keyed by UID. Without label_file the label column is read from the
	// conn.log itself.
	ConnLog   string   `yaml:"conn_log"`
	LabelFile string   `yaml:"label_file"`
	Columns   *Columns `yaml:"columns"`
	// Positive lists label values that mean C2 (case-insensitive).
	// Default: c2, malicious, malware, 1, true.
	Positive []string `yaml:"positive"`
	// MinJoin fails the run when the matched fraction of Zeek connections
	// is lower (default 0: report only).
	MinJoin float64 `yaml:"min_join"`
	// per-capture: C2 endpoints (client + server IP or name).
	C2 []Endpoint `yaml:"c2"`
	// time-window: a series is positive when its endpoints match and an
	// event falls inside a window.
	Windows []Window `yaml:"windows"`
}

// Columns maps the reader's fields to column names in the label sources.
// Every name is configurable because the TQH-C2 schema is not confirmed
// until its README is read (docs/datasets/tqh-c2.md). Empty → default.
type Columns struct {
	TS        string `yaml:"ts"`        // default ts
	UID       string `yaml:"uid"`       // default uid
	OrigH     string `yaml:"orig_h"`    // default id.orig_h
	OrigP     string `yaml:"orig_p"`    // default id.orig_p
	RespH     string `yaml:"resp_h"`    // default id.resp_h
	RespP     string `yaml:"resp_p"`    // default id.resp_p
	Proto     string `yaml:"proto"`     // default proto
	Duration  string `yaml:"duration"`  // default duration
	Label     string `yaml:"label"`     // default label
	Framework string `yaml:"framework"` // optional per-row metadata in the label file
	Transport string `yaml:"transport"`
	Sleep     string `yaml:"sleep"`
	Jitter    string `yaml:"jitter"`
}

// Window is a time-window label.
type Window struct {
	Start  string `yaml:"start"` // RFC 3339 or unix seconds
	End    string `yaml:"end"`
	Client string `yaml:"client"`
	Server string `yaml:"server"` // IP or name
}

type window struct {
	start, end float64
	ep         Endpoint
}

// Endpoint labels C2 traffic.
type Endpoint struct {
	Client string `yaml:"client"`
	Server string `yaml:"server"` // IP or name
}

func (c *Columns) withDefaults(base *Columns) Columns {
	out := Columns{TS: "ts", UID: "uid", OrigH: "id.orig_h", OrigP: "id.orig_p", RespH: "id.resp_h", RespP: "id.resp_p",
		Proto: "proto", Duration: "duration", Label: "label"}
	for _, src := range []*Columns{base, c} {
		if src == nil {
			continue
		}
		set := func(dst *string, v string) {
			if v != "" {
				*dst = v
			}
		}
		set(&out.TS, src.TS)
		set(&out.UID, src.UID)
		set(&out.OrigH, src.OrigH)
		set(&out.OrigP, src.OrigP)
		set(&out.RespH, src.RespH)
		set(&out.RespP, src.RespP)
		set(&out.Proto, src.Proto)
		set(&out.Duration, src.Duration)
		set(&out.Label, src.Label)
		set(&out.Framework, src.Framework)
		set(&out.Transport, src.Transport)
		set(&out.Sleep, src.Sleep)
		set(&out.Jitter, src.Jitter)
	}
	return out
}

// LoadManifest reads and validates a manifest (files are not checked;
// see Resolve).
func LoadManifest(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m, err := ParseManifest(b)
	if err != nil {
		return nil, fmt.Errorf("manifest %s: %w", path, err)
	}
	m.dir = filepath.Dir(path)
	for i := range m.Captures {
		c := &m.Captures[i]
		c.Path = m.abs(c.Path)
		if l := c.Labels; l != nil {
			if l.ConnLog != "" {
				l.ConnLog = m.abs(l.ConnLog)
			}
			if l.LabelFile != "" {
				l.LabelFile = m.abs(l.LabelFile)
			}
		}
	}
	return m, nil
}

func (m *Manifest) abs(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(m.dir, p)
}

// ParseManifest decodes strictly and validates.
func ParseManifest(b []byte) (*Manifest, error) {
	var m Manifest
	if err := safeUnmarshal(b, &m, yaml.DisallowUnknownField()); err != nil {
		return nil, err
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func parseCIDRs(ss []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range ss {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("internal CIDR %q: %w", s, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func parseTime(s string) (float64, error) {
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return 0, fmt.Errorf("time %q: want RFC 3339 or unix seconds", s)
	}
	return float64(t.UnixNano()) / 1e9, nil
}

func oneOf(v string, set ...string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

func (m *Manifest) validate() error {
	switch m.Version {
	case 0:
		m.Version = 1
	case 1, ManifestVersion:
	default:
		return fmt.Errorf("version %d: this build reads manifest versions 1 and %d", m.Version, ManifestVersion)
	}
	if len(m.Captures) == 0 {
		return errors.New("no captures")
	}
	var err error
	if m.internal, err = parseCIDRs(m.Internal); err != nil {
		return err
	}
	var errs []error
	for i := range m.Captures {
		c := &m.Captures[i]
		if e := m.validateCapture(c); e != nil {
			errs = append(errs, fmt.Errorf("captures[%d] %s: %w", i, c.Path, e))
		}
	}
	return errors.Join(errs...)
}

func (m *Manifest) validateCapture(c *Capture) error {
	if c.Path == "" {
		return errors.New("path is required")
	}
	if _, err := filepath.Match(c.Path, ""); err != nil {
		return fmt.Errorf("bad glob: %w", err)
	}
	if m.Version == 1 {
		if c.Role != "" || c.Labels != nil {
			return errors.New("role/labels need version: 2")
		}
		switch {
		case c.Benign:
			c.Role = RoleBenign
		case c.BackgroundBenign:
			c.Role = RoleMixed
		default:
			c.Role = RoleC2
		}
		if !c.Benign {
			if len(c.C2) == 0 {
				return errors.New("not benign and has no c2 labels")
			}
			c.Labels = &Labels{Source: LabelPerCapture, C2: c.C2}
		}
	} else if c.Benign || len(c.C2) > 0 || c.BackgroundBenign {
		return errors.New("benign / c2 / background_benign are version-1 keys; use role and labels")
	}
	if !oneOf(c.Role, RoleC2, RoleBenign, RoleMixed) {
		return fmt.Errorf("role %q: want c2, benign or mixed", c.Role)
	}
	if c.Licence != "" && !oneOf(c.Licence, "ccby", "internal", "own", "synthetic") {
		return fmt.Errorf("licence %q: want ccby, internal, own or synthetic", c.Licence)
	}
	if c.Tasking != "" && !oneOf(c.Tasking, "yes", "no", "unknown") {
		return fmt.Errorf("tasking %q: want yes, no or unknown", c.Tasking)
	}
	if c.Sleep < 0 || c.Jitter < 0 || c.Jitter > 100 {
		return errors.New("sleep must be ≥ 0 and jitter a percentage in [0, 100]")
	}
	var err error
	if c.internal, err = parseCIDRs(c.Internal); err != nil {
		return err
	}
	if c.ExpectedHostHours < 0 || c.ExpectedHostHours > 0 && c.Role != RoleBenign {
		return errors.New("expected_host_hours is for role: benign only, and must be ≥ 0")
	}
	l := c.Labels
	src := LabelNone
	if l != nil {
		src = l.Source
	}
	if c.Role == RoleBenign {
		if src != LabelNone {
			return errors.New("a benign capture takes no labels (source: none)")
		}
		return nil
	}
	switch src {
	case LabelNone:
		return fmt.Errorf("role %s needs a label source (zeek-uid, per-capture or time-window)", c.Role)
	case LabelZeekUID:
		if l.ConnLog == "" {
			return errors.New("zeek-uid labels need conn_log")
		}
		if _, err := filepath.Match(l.ConnLog, ""); err != nil {
			return fmt.Errorf("bad conn_log glob: %w", err)
		}
		if len(l.C2) > 0 || len(l.Windows) > 0 {
			return errors.New("zeek-uid labels take no c2 or windows")
		}
	case LabelPerCapture:
		if len(l.C2) == 0 {
			return errors.New("per-capture labels need c2 endpoints")
		}
		if l.ConnLog != "" || l.LabelFile != "" || len(l.Windows) > 0 {
			return errors.New("per-capture labels take only c2")
		}
	case LabelTimeWindow:
		if len(l.Windows) == 0 {
			return errors.New("time-window labels need windows")
		}
		for _, w := range l.Windows {
			s, err := parseTime(w.Start)
			if err != nil {
				return err
			}
			e, err := parseTime(w.End)
			if err != nil {
				return err
			}
			if e <= s {
				return fmt.Errorf("window %s–%s ends before it starts", w.Start, w.End)
			}
			c.windows = append(c.windows, window{s, e, Endpoint{w.Client, w.Server}})
		}
	default:
		return fmt.Errorf("label source %q: want none, zeek-uid, per-capture or time-window", src)
	}
	if l.MinJoin < 0 || l.MinJoin > 1 {
		return errors.New("min_join is a fraction in [0, 1]")
	}
	for _, ep := range l.C2 {
		if ep.Client == "" && ep.Server == "" {
			return errors.New("an empty c2 endpoint labels everything")
		}
	}
	return nil
}

// Unit is one engine run: one file, or the rotated segments of one capture.
type Unit struct {
	Capture *Capture
	Files   []string
	Name    string // display name
}

// Resolve expands globs and checks every referenced file exists. Missing
// files are errors: a run on half a dataset would report numbers that
// look complete.
func (m *Manifest) Resolve() ([]Unit, error) {
	var units []Unit
	var errs []error
	for i := range m.Captures {
		c := &m.Captures[i]
		files, err := expand(c.Path)
		if err != nil {
			errs = append(errs, fmt.Errorf("captures[%d]: %w", i, err))
			continue
		}
		if l := c.Labels; l != nil {
			if l.ConnLog != "" {
				if _, err := expand(l.ConnLog); err != nil {
					errs = append(errs, fmt.Errorf("captures[%d] conn_log: %w", i, err))
				}
			}
			if l.LabelFile != "" {
				if _, err := os.Stat(l.LabelFile); err != nil {
					errs = append(errs, fmt.Errorf("captures[%d] label_file: %w", i, err))
				}
			}
		}
		if c.Rotated {
			units = append(units, Unit{Capture: c, Files: files, Name: rotatedName(files)})
			continue
		}
		for _, f := range files {
			units = append(units, Unit{Capture: c, Files: []string{f}, Name: filepath.Base(f)})
		}
	}
	return units, errors.Join(errs...)
}

func expand(pattern string) ([]string, error) {
	if !strings.ContainsAny(pattern, "*?[") {
		st, err := os.Stat(pattern)
		if err != nil {
			return nil, fmt.Errorf("missing file %s", pattern)
		}
		if st.IsDir() {
			return nil, fmt.Errorf("%s is a directory (use a glob)", pattern)
		}
		return []string{pattern}, nil
	}
	m, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range m {
		if st, err := os.Stat(f); err == nil && !st.IsDir() {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no files match %s", pattern)
	}
	sort.Strings(files) // rotation order: tcpdump -C/-W and dumpcap -b name segments in sequence
	return files, nil
}

func rotatedName(files []string) string {
	if len(files) == 1 {
		return filepath.Base(files[0])
	}
	return fmt.Sprintf("%s (+%d rotated)", filepath.Base(files[0]), len(files)-1)
}

func (c *Capture) isSynthetic(m *Manifest) bool {
	return m.Synthetic || c.Synthetic || c.Licence == "synthetic" || strings.HasPrefix(c.Framework, "synth:")
}
