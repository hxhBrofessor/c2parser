package engine

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// VA-0 S1b (V1a-1): AST guard. In any function that adds a non-generic signal
// (framework_specific / sigma_attribution / mixed / unknown) via a resolvable
// a.add(stats.Signal{Name: ...}) — a string literal or a registered
// family-prefix construction — a plain a.evidence / a.frames call must be
// converted to evidenceFrom / framesFrom or carry a justification on the
// allow-list below. This keeps framework-specific evidence/frames out of BLIND
// output. FULL output is unaffected.

// evlinkAllow: "funcName|callee|tag" -> justification. tag is the first string
// literal argument for evidence (the format string), or "frames" for frames.
// Every entry is a GENERIC observed-data companion line (S1b audit, design
// §5b): it names no framework — framework attribution is carried only by the
// suppressed signal's Detail. The two non-generic framework *frame* sites were
// converted to framesFrom in S1a and so never reach this guard.
var evlinkAllow = map[string]string{
	"scoreBehavior|evidence|SNI: %s":                                                   "observed TLS SNI (data), not a framework name",
	"scoreBehavior|evidence|%d connections, %s up, %s down, longest %s":                "observed channel volume",
	"scoreBehavior|evidence|TLS: JA3 %s, JA4 %s, SNI %s":                               "observed TLS fingerprints/SNI (data)",
	"scoreBehavior|frames|frames":                                                      "channel first-frame activity marker",
	"scoreCarriers|evidence|WebSocket: %d client / %d server messages, %s up, %s down": "observed WebSocket volume",
	"scoreCarriers|frames|frames":                                                      "carrier activity frames",
	"scoreDNS|evidence|longest names: %s":                                              "observed DNS query names (data, not a framework label)",
	"scoreDNS|evidence|examples: %s":                                                   "observed DNS names (data)",
	"scoreDNS|frames|frames":                                                           "DNS first-frame activity marker",
	"scoreHTTP|evidence|%d requests / %d responses; %s up, %s down":                    "observed HTTP volume",
	"scoreHTTP|evidence|User-Agent: %s":                                                "observed UA string; framework attribution via suppressed hdr:/default_profile signals (content-level default-UA sanitization tracked OPEN-5)",
	"scoreHTTP|evidence|methods: %s; URIs: %s":                                         "observed methods/URIs (data)",
	"scoreHTTP|frames|frames":                                                          "HTTP first/response activity frames",
	"scoreRawStreams|evidence|%d connections, %s up, %s down":                          "observed raw-stream volume",
	"scoreRawStreams|frames|frames":                                                    "raw-stream activity frames",
	"scoreSMB|evidence|SMB session authenticated as: %s":                               "observed SMB authenticated user (session fact), not a framework name",
	"scoreSMB|frames|frames":                                                           "pipe open/first activity frames; framework magic frames are the converted framesFrom site",
}

// familyPrefixesNonGeneric are the registered dynamic families that can carry a
// non-generic class; a construction "<prefix>" + expr triggers the guard.
var familyPrefixesNonGeneric = []string{"default_profile:", "sigma:", "uri_shape:", "hdr:", "ioc:", "sig:", "cs_config:"}

func TestVA0EvidenceLinkDiscipline(t *testing.T) {
	pol := newEvidencePolicy(FrameworkBlindMode)
	fset := gotoken.NewFileSet()
	files, _ := filepath.Glob("*.go")
	var flagged []string
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		base := filepath.Base(path)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			addsNonGeneric := false
			type call struct{ callee, tag, pos string }
			var plain []call
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "add":
					if name, resolvable := addedSignalName(ce); resolvable {
						if nameIsSuppressible(pol, name) {
							addsNonGeneric = true
						}
					}
				case "evidence", "frames":
					tag := "frames"
					if sel.Sel.Name == "evidence" {
						tag = firstStringLit(ce)
					}
					plain = append(plain, call{sel.Sel.Name, tag, fset.Position(ce.Pos()).String()})
				}
				return true
			})
			if !addsNonGeneric {
				continue
			}
			for _, c := range plain {
				key := fn.Name.Name + "|" + c.callee + "|" + c.tag
				if _, ok := evlinkAllow[key]; ok {
					continue
				}
				flagged = append(flagged, base+" "+fn.Name.Name+"(): plain "+c.callee+" at "+c.pos+"  key="+key)
			}
		}
	}
	sort.Strings(flagged)
	if len(flagged) > 0 {
		t.Errorf("%d unlinked evidence/frames call(s) in non-generic-signal functions (convert to *From or allow-list):\n%s",
			len(flagged), strings.Join(flagged, "\n"))
	}
}

// addedSignalName returns the Name of a stats.Signal composite literal passed to
// a.add, as a static string (literal) or a family prefix ("sigma:" etc. for a
// "<prefix>"+expr construction). resolvable is false when the name cannot be
// determined statically (then the call does not trigger the guard).
func addedSignalName(ce *ast.CallExpr) (string, bool) {
	if len(ce.Args) != 1 {
		return "", false
	}
	cl, ok := ce.Args[0].(*ast.CompositeLit)
	if !ok {
		return "", false
	}
	for _, el := range cl.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if id, ok := kv.Key.(*ast.Ident); !ok || id.Name != "Name" {
			continue
		}
		return staticNameExpr(kv.Value)
	}
	return "", false
}

func staticNameExpr(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		return strings.Trim(v.Value, "`\""), true
	case *ast.BinaryExpr:
		// "<prefix>" + something -> the prefix (leftmost string literal)
		if s, ok := staticNameExpr(v.X); ok {
			return s, true
		}
	}
	return "", false
}

// nameIsSuppressible reports whether a statically-resolved signal name would be
// dropped in BLIND: an exact literal whose class is suppressed, or a
// "<family-prefix>"+expr construction whose family can carry a suppressed class
// (conservative: the suffix is unknown statically, so require linkage). Generic
// and derived_correlation names (retained in BLIND) do not trigger the guard.
func nameIsSuppressible(pol *EvidencePolicy, name string) bool {
	// A bare family prefix (from a "<prefix>"+expr construction) triggers only
	// if that family can carry a suppressed class. All-generic families
	// (rpc:, encoded_payload_in_) do not trigger.
	if _, isFamily := pol.reg.Families[name]; isFamily {
		for _, p := range familyPrefixesNonGeneric {
			if name == p {
				return true
			}
		}
		return false
	}
	return pol.suppresses(name)
}

func firstStringLit(ce *ast.CallExpr) string {
	for _, a := range ce.Args {
		if bl, ok := a.(*ast.BasicLit); ok {
			return strings.Trim(bl.Value, "`\"")
		}
	}
	return "?"
}
