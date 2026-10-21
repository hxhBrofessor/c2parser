package data_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"c2parser/data"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTrackedEvidenceJSONAndCobaltD07Crosswalk(t *testing.T) {
	paths, err := filepath.Glob("../evidence/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("evidence JSON inventory: %v (%d files)", err, len(paths))
	}
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err := json.Unmarshal(b, &value); err != nil {
			t.Errorf("%s: invalid JSON: %v", path, err)
		}
		if len(b) == 0 || b[len(b)-1] != '\n' {
			t.Errorf("%s: expected LF termination", path)
		}
	}
	var debt struct {
		Items []struct {
			ID           string `json:"id"`
			DebtID       string `json:"debt_id"`
			SourceCommit string `json:"source_commit"`
			SourcePath   string `json:"source_path"`
			SourceLines  string `json:"source_lines"`
			MatchLines   string `json:"match_lines"`
		} `json:"items"`
	}
	b, err := os.ReadFile("../evidence/cobaltstrike-debt-register.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &debt); err != nil {
		t.Fatal(err)
	}
	var cross struct {
		Predicates []struct {
			ID          string `json:"id"`
			DebtID      string `json:"debt_id"`
			SourcePath  string `json:"source_path"`
			SourceLines string `json:"source_lines"`
			MatchLines  string `json:"match_lines"`
		} `json:"ordered_predicates"`
	}
	b, err = os.ReadFile("../evidence/cobaltstrike-predicate-source-map.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &cross); err != nil {
		t.Fatal(err)
	}
	if len(debt.Items) != 4 || len(cross.Predicates) != 4 {
		t.Fatalf("expected four D-07 rows: debt=%d source=%d", len(debt.Items), len(cross.Predicates))
	}
	profiles, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	var items []data.Item
	for _, fw := range profiles.Frameworks {
		if fw.ID == "cobaltstrike" {
			items = fw.FieldGroups["http"].Items
		}
	}
	if len(items) != 4 {
		t.Fatalf("loaded cobalt items=%d", len(items))
	}
	for i := range debt.Items {
		d, c := debt.Items[i], cross.Predicates[i]
		if d.ID != c.ID || d.DebtID != c.DebtID || d.SourceCommit != "425897e8c36005e001e6f6254ede16117194f9d2" || d.SourcePath != c.SourcePath || d.SourceLines != c.SourceLines || d.MatchLines != c.MatchLines || items[i].ID != d.ID || items[i].DebtID != d.DebtID || items[i].Locator != "repo@"+d.SourceCommit+":"+d.SourcePath+":"+d.SourceLines {
			t.Errorf("D-07 mapping %d not one-to-one", i)
		}
	}
}

func TestEmbeddedCovenantAssetAndFreshCopies(t *testing.T) {
	first, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	if first.SchemaVersion != 1 || len(first.Frameworks) != 4 || first.Frameworks[0].ID != "covenant" || first.Frameworks[1].ID != "merlin" || first.Frameworks[3].ID != "cobaltstrike" {
		t.Fatalf("unexpected embedded profile document: %#v", first)
	}
	if len(first.Frameworks[0].FieldGroups["http"].Items) != 8 {
		t.Fatalf("unexpected embedded Covenant HTTP inventory: %#v", first.Frameworks[0].FieldGroups["http"].Items)
	}
	first.Frameworks[0].FieldGroups["http"] = data.FieldGroup{}
	second, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Frameworks) != 4 || len(second.Frameworks[0].FieldGroups["http"].Items) != 8 || len(second.Frameworks[1].FieldGroups["http"].Items) != 4 || len(second.Frameworks[2].FieldGroups["http"].Items) != 6 || len(second.Frameworks[3].FieldGroups["http"].Items) != 4 {
		t.Fatalf("caller mutation reached package asset: %#v", second)
	}
	third, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(second, third) {
		t.Fatal("repeated embedded loads differ")
	}
}

func TestStrictScalarKinds(t *testing.T) {
	base := string(readFixture(t, "valid-profile.yaml"))
	cases := []struct{ name, old, replacement string }{
		{"quoted schema version", "schema_version: 1", `schema_version: "1"`},
		{"float schema version", "schema_version: 1", "schema_version: 1.0"},
		{"integer framework id", "id: sample_framework", "id: 17"},
		{"integer alias", "aliases: [sample]", "aliases: [17]"},
		{"integer evidence", "evidence: SOURCE-CONFIRMED", "evidence: 17"},
		{"string verify flag", "verify: true", `verify: "true"`},
		{"integer source id", "id: test-only-source", "id: 17"},
		{"boolean citation", "citation: test fixture citation; not an external provenance claim", "citation: true"},
		{"boolean revision", "revision: 0123456789abcdef0123456789abcdef01234567", "revision: false"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.Replace(base, tc.old, tc.replacement, 1)
			if input == base {
				t.Fatal("test mutation did not apply")
			}
			if _, err := data.ParseProfiles([]byte(input)); err == nil {
				t.Fatal("expected strict scalar-kind rejection")
			}
		})
	}
}

func TestUnresolvedEvidenceRequiresExplicitSourceKey(t *testing.T) {
	for _, evidence := range []string{"UNKNOWN", "BLOCKED_MISSING_SOURCE"} {
		t.Run(evidence, func(t *testing.T) {
			input := []byte("schema_version: 1\nframeworks:\n  - id: unresolved_fixture\n    field_groups:\n      http:\n        evidence: " + evidence + "\n        verify: true\n        reason: status recorded for test\n        items: []\n")
			if _, err := data.ParseProfiles(input); err == nil || !strings.Contains(err.Error(), "source") {
				t.Fatalf("missing explicit source key was not rejected for %s: %v", evidence, err)
			}
		})
	}
}

func TestCovenantItemsHaveClosedTypedGrammar(t *testing.T) {
	asset, err := os.ReadFile("framework-fingerprints.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.ParseProfiles(asset); err != nil {
		t.Fatalf("production profile rejected: %v", err)
	}
	cases := []struct{ name, old, replacement string }{
		{"unknown kind", "kind: uri_exact", "kind: regex"},
		{"wrong scalar type", "weight: 0.25", "weight: true"},
		{"unknown item key", "            kind: uri_exact", "            extra: true\n            kind: uri_exact"},
		{"non-string values entry", `              - "// Hello World! "`, "              - true"},
		{"missing item debt id", "            debt_id: B33-D07-COV-HTTP-001\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.Replace(string(asset), tc.old, tc.replacement, 1)
			if input == string(asset) {
				t.Fatal("test mutation did not apply")
			}
			if _, err := data.ParseProfiles([]byte(input)); err == nil {
				t.Fatal("expected closed-grammar rejection")
			}
		})
	}
}

func TestCovenantDebtRegisterInventory(t *testing.T) {
	p, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	g := p.Frameworks[0].FieldGroups["http"]
	want := map[string]struct {
		debt, kind, feature, locator string
		weight                       float64
	}{
		"covenant-http-uri-index":         {"B33-D07-COV-HTTP-001", "uri_exact", "URI /en-us/index.html", "103-104", .25},
		"covenant-http-uri-docs":          {"B33-D07-COV-HTTP-002", "uri_exact", "URI /en-us/docs.html", "103-104", .25},
		"covenant-http-uri-test":          {"B33-D07-COV-HTTP-003", "uri_exact", "URI /en-us/test.html", "103-104", .25},
		"covenant-http-user-agent":        {"B33-D07-COV-HTTP-004", "header_exact", "Chrome/41.0.2228.0 User-Agent", "106-107", .45},
		"covenant-http-cookie":            {"B33-D07-COV-HTTP-005", "header_contains", "Cookie SESSIONID=1552332971750", "109-110", .9},
		"covenant-http-post-template":     {"B33-D07-COV-HTTP-006", "body_prefix", "POST body template i=a19ea23062db…&data=", "112-113", .9},
		"covenant-http-server":            {"B33-D07-COV-HTTP-007", "header_exact", "Server: Microsoft-IIS/7.5", "156-157", .15},
		"covenant-http-response-template": {"B33-D07-COV-HTTP-008", "body_contains_any", "Hello World! response template", "159-160", .4},
	}
	if g.Evidence != data.EvidenceUnknown || g.Verify || g.Source == nil || g.Source.Revision != "425897e8c36005e001e6f6254ede16117194f9d2" || !strings.Contains(strings.ToLower(g.Reason), "external provenance pending") || len(g.Items) != len(want) {
		t.Fatalf("D-07 group status mismatch: %#v", g)
	}
	seenDebt := map[string]bool{}
	ordered := []string{"covenant-http-uri-index", "covenant-http-uri-docs", "covenant-http-uri-test", "covenant-http-user-agent", "covenant-http-cookie", "covenant-http-post-template", "covenant-http-server", "covenant-http-response-template"}
	for i, item := range g.Items {
		if i >= len(ordered) || item.ID != ordered[i] {
			t.Errorf("noncanonical behavior order at %d: got %q", i, item.ID)
		}
		expect, ok := want[item.ID]
		if !ok || expect.debt != item.DebtID || expect.kind != item.Kind || expect.feature != item.Feature || expect.weight != item.Weight || !strings.HasSuffix(item.Locator, ":"+expect.locator) {
			t.Errorf("unexpected Covenant HTTP item: %#v", item)
		}
		if seenDebt[item.DebtID] {
			t.Errorf("duplicate behavior-debt ID %q", item.DebtID)
		}
		seenDebt[item.DebtID] = true
	}
}

func TestValidFixtureAndGroupSemantics(t *testing.T) {
	p, err := data.ParseProfiles(readFixture(t, "valid-profile.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Frameworks) != 1 || len(p.Frameworks[0].FieldGroups) != 3 {
		t.Fatalf("unexpected parsed fixture: %#v", p)
	}
	if p.Frameworks[0].FieldGroups["cert"].Source != nil || p.Frameworks[0].FieldGroups["dns"].Source != nil {
		t.Fatal("null-source fixture groups should remain source-null")
	}
	for _, group := range []string{"cert", "dns"} {
		g := p.Frameworks[0].FieldGroups[group]
		if !g.Verify || len(g.Items) != 0 || strings.TrimSpace(g.Reason) == "" {
			t.Fatalf("pending %s should remain declared-but-empty: %#v", group, g)
		}
	}
	if p.Frameworks[0].Aliases[0] != "sample" {
		t.Fatal("alias not parsed")
	}
}

func TestUnresolvedEvidenceCanCiteStatusSource(t *testing.T) {
	input := []byte(`schema_version: 1
frameworks:
  - id: unresolved_fixture
    field_groups:
      http:
        evidence: UNKNOWN
        verify: true
        source:
          id: status-record
          citation: test-only record of unresolved provenance status
          revision: 0123456789abcdef0123456789abcdef01234567
        reason: External fingerprint provenance remains unresolved.
        items: []
      dns:
        evidence: BLOCKED_MISSING_SOURCE
        verify: true
        source:
          id: blocked-status-record
          citation: test-only record of missing source status
          revision: 0123456789abcdef0123456789abcdef01234567
        reason: Required behavior source is unavailable.
        items: []
`)
	if _, err := data.ParseProfiles(input); err != nil {
		t.Fatalf("valid status-source records rejected: %v", err)
	}
}

func TestActiveHTTPItemsRemainAccepted(t *testing.T) {
	base := string(readFixture(t, "valid-profile.yaml"))
	base = strings.Replace(base, "id: sample_framework", "id: covenant", 1)
	base = strings.Replace(base, "        verify: true", "        verify: false", 1)
	base = strings.Replace(base, "        items: []", `        items:
          - id: active-http-fixture
            debt_id: ACTIVE-TEST-001
            code_locator: repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:103-104
            kind: uri_exact
            message: request
            value: /active
            feature: active fixture URI
            weight: 0.25`, 1)
	p, err := data.ParseProfiles([]byte(base))
	if err != nil {
		t.Fatalf("verify:false HTTP item rejected: %v", err)
	}
	g := p.Frameworks[0].FieldGroups["http"]
	if g.Verify || len(g.Items) != 1 || g.Items[0].Value != "/active" {
		t.Fatalf("active HTTP fixture mismatch: %#v", g)
	}
}

func TestPendingGroupsRequireExactlyEmptyItems(t *testing.T) {
	const item = `
          - id: pending-fixture-item
            debt_id: PENDING-TEST-001
            code_locator: repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:103-104
            kind: uri_exact
            message: request
            value: /fixture
            feature: fixture URI
            weight: 0.25`
	for _, group := range []string{"http", "cert", "dns", "blob", "transport", "version_map"} {
		t.Run(group, func(t *testing.T) {
			input := []byte(`schema_version: 1
frameworks:
  - id: pending_fixture
    field_groups:
      ` + group + `:
        evidence: UNKNOWN
        verify: true
        source: null
        reason: Pending status recorded for a parser test.
        items: []
`)
			if _, err := data.ParseProfiles(input); err != nil {
				t.Fatalf("declared empty pending group rejected: %v", err)
			}
			input = []byte(strings.Replace(string(input), "        items: []", "        items:"+item, 1))
			if _, err := data.ParseProfiles(input); err == nil || !strings.Contains(err.Error(), "PENDING_GROUP_ITEMS_NOT_EMPTY") {
				t.Fatalf("pending items did not fail at the pending contract: %v", err)
			}
		})
	}
}

func TestPendingItemsSequenceShapeRemainsRequired(t *testing.T) {
	base := string(readFixture(t, "valid-profile.yaml"))
	for _, tc := range []struct{ name, replacement string }{
		{"null", "items: null"},
		{"mapping", "items: {}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.Replace(base, "items: []", tc.replacement, 1)
			if _, err := data.ParseProfiles([]byte(input)); err == nil || !strings.Contains(strings.ToLower(err.Error()), "items") {
				t.Fatalf("malformed pending item sequence accepted: %v", err)
			}
		})
	}
}

func TestSourcedEvidenceEnumsAndEmptyGroups(t *testing.T) {
	base := string(readFixture(t, "valid-profile.yaml"))
	for _, evidence := range []string{"SOURCE-CONFIRMED", "CAPTURE-OBSERVED", "SYNTHETIC-MODELED"} {
		input := strings.Replace(base, "SOURCE-CONFIRMED", evidence, 1)
		if _, err := data.ParseProfiles([]byte(input)); err != nil {
			t.Fatalf("%s rejected: %v", evidence, err)
		}
	}
	pending := strings.Replace(base, "        verify: true", "        verify: false", 1)
	if _, err := data.ParseProfiles([]byte(pending)); err != nil {
		t.Fatalf("verify:false sourced record rejected: %v", err)
	}
	emptyGroups := []byte("schema_version: 1\nframeworks:\n  - id: no_groups_yet\n    field_groups: {}\n")
	if _, err := data.ParseProfiles(emptyGroups); err != nil {
		t.Fatalf("empty field_groups should be valid: %v", err)
	}
}

func TestPinnedSemanticVersionRevision(t *testing.T) {
	base := string(readFixture(t, "valid-profile.yaml"))
	base = strings.Replace(base, "0123456789abcdef0123456789abcdef01234567", "v2.4.1", 1)
	if _, err := data.ParseProfiles([]byte(base)); err != nil {
		t.Fatalf("pinned semantic version rejected: %v", err)
	}
}

func TestParsedValuesAreIndependent(t *testing.T) {
	fixture := readFixture(t, "valid-profile.yaml")
	first, err := data.ParseProfiles(fixture)
	if err != nil {
		t.Fatal(err)
	}
	first.Frameworks[0].Aliases[0] = "changed"
	first.Frameworks[0].FieldGroups["http"].Source.ID = "changed"
	second, err := data.ParseProfiles(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if second.Frameworks[0].Aliases[0] != "sample" || second.Frameworks[0].FieldGroups["http"].Source.ID != "test-only-source" {
		t.Fatal("caller mutation changed a later parsed value")
	}
}

func TestD07ValidationOnlyFixture(t *testing.T) {
	p, err := data.ParseProfiles(readFixture(t, "d07-legacy-pointer.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	g := p.Frameworks[0].FieldGroups["http"]
	if g.Evidence != data.EvidenceUnknown || g.Verify || g.Source == nil {
		t.Fatalf("D-07 fixture not represented: %#v", g)
	}
}

func TestRejectInvalidDocuments(t *testing.T) {
	base := string(readFixture(t, "valid-profile.yaml"))
	cases := []struct{ name, input, want string }{
		{"missing source key", strings.Replace(base, "        source:\n          id: test-only-source\n          citation: test fixture citation; not an external provenance claim\n          revision: 0123456789abcdef0123456789abcdef01234567\n", "", 1), "source"},
		{"null sourced status", strings.Replace(base, "        evidence: SOURCE-CONFIRMED\n        verify: true\n        source:\n          id: test-only-source\n          citation: test fixture citation; not an external provenance claim\n          revision: 0123456789abcdef0123456789abcdef01234567\n", "        evidence: SOURCE-CONFIRMED\n        verify: true\n        source: null\n", 1), "source"},
		{"null capture source", strings.Replace(strings.Replace(base, "SOURCE-CONFIRMED", "CAPTURE-OBSERVED", 1), "        source:\n          id: test-only-source\n          citation: test fixture citation; not an external provenance claim\n          revision: 0123456789abcdef0123456789abcdef01234567\n", "        source: null\n", 1), "source"},
		{"null synthetic source", strings.Replace(strings.Replace(base, "SOURCE-CONFIRMED", "SYNTHETIC-MODELED", 1), "        source:\n          id: test-only-source\n          citation: test fixture citation; not an external provenance claim\n          revision: 0123456789abcdef0123456789abcdef01234567\n", "        source: null\n", 1), "source"},
		{"missing unresolved reason", strings.Replace(base, "        reason: Source provenance is not yet available.\n", "", 1), "reason"},
		{"empty unresolved reason", strings.Replace(base, "Source provenance is not yet available.", "'   '", 1), "reason"},
		{"invalid evidence", strings.Replace(base, "SOURCE-CONFIRMED", "SOURCE-CLAIMED", 1), "evidence"},
		{"unsupported schema", strings.Replace(base, "schema_version: 1", "schema_version: 2", 1), "schema_version"},
		{"duplicate key", strings.Replace(base, "schema_version: 1", "schema_version: 1\nschema_version: 1", 1), ""},
		{"unknown root key", strings.Replace(base, "schema_version: 1", "extra_root: true\nschema_version: 1", 1), ""},
		{"unknown framework key", strings.Replace(base, "  - id: sample_framework", "  - extra_framework: true\n    id: sample_framework", 1), ""},
		{"unknown group key", strings.Replace(base, "        verify: true", "        extra_group: true\n        verify: true", 1), ""},
		{"unknown source key", strings.Replace(base, "          id: test-only-source", "          extra_source: true\n          id: test-only-source", 1), ""},
		{"unknown field group", strings.Replace(base, "      http:", "      alien:\n        evidence: UNKNOWN\n        verify: true\n        source: null\n        reason: unknown fixture group\n        items: []\n      http:", 1), "field group"},
		{"duplicate framework id", base + "\n  - id: sample_framework\n    field_groups: {}\n", "duplicate framework ID"},
		{"duplicate alias", base + "\n  - id: another_framework\n    aliases: [sample]\n    field_groups: {}\n", "duplicate alias"},
		{"nonempty items", strings.Replace(base, "        items: []", "        items: [unexpected]", 1), "items"},
		{"anchor", "schema_version: &v 1\nframeworks: []\n", "anchors"},
		{"alias", "schema_version: 1\nframeworks: *v\n", ""},
		{"custom tag", "schema_version: !custom 1\nframeworks: []\n", "tags"},
		{"malformed type", "schema_version: one\nframeworks: []\n", ""},
		{"multiple documents", "schema_version: 1\nframeworks: []\n---\nschema_version: 1\nframeworks: []\n", "exactly one document"},
		{"items missing", strings.Replace(base, "        items: []\n", "", 1), "items"},
		{"field_groups missing", strings.Replace(base, "    field_groups:\n", "    no_groups:\n", 1), "field_groups"},
		{"canonical id", strings.Replace(base, "sample_framework", "SampleFramework", 1), "snake_case"},
		{"null aliases", strings.Replace(base, "aliases: [sample]", "aliases: null", 1), "aliases"},
		{"null reason", strings.Replace(base, "reason: Source provenance is not yet available.", "reason: null", 1), "reason"},
		{"alias/id collision", base + "\n  - id: sample\n    field_groups: {}\n", "collides"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := data.ParseProfiles([]byte(tc.input))
			if err == nil {
				t.Fatal("expected rejection")
			}
			if tc.want != "" && !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Fatalf("wrong rejection: %v; want %q", err, tc.want)
			}
		})
	}
}

func TestD07RejectsInvalidPointersAndReason(t *testing.T) {
	base := string(readFixture(t, "d07-legacy-pointer.yaml"))
	cases := []struct{ name, old, replacement, want string }{
		{"null source", "          id: test-only-v11a-pointer\n          citation: test fixture pointer; not an external provenance claim\n          revision: 425897e8c36005e001e6f6254ede16117194f9d2\n          locator: repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:78\n", "", "verify"},
		{"wrong commit", "revision: 425897e8c36005e001e6f6254ede16117194f9d2", "revision: 525897e8c36005e001e6f6254ede16117194f9d2", "revision"},
		{"unpinned locator", "repo@425897e8c36005e001e6f6254ede16117194f9d2:", "repo@main:", "locator"},
		{"invalid path", ":internal/engine/httpdefaults.go:78", ":../internal/engine/httpdefaults.go:78", "path"},
		{"missing locator", "          locator: repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:78\n", "", "locator"},
		{"missing reason", "        reason: External provenance is pending for this test-only legacy pointer.\n", "", "reason"},
		{"wrong reason", "External provenance is pending", "Source was reviewed", "reason"},
		{"bad locator suffix", "httpdefaults.go:78", "httpdefaults.go:0", "locator"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := base
			if tc.old != "" {
				input = strings.Replace(input, tc.old, tc.replacement, 1)
			} else if tc.name == "missing reason" {
				input = strings.Replace(input, tc.old, tc.replacement, 1)
			}
			if tc.name == "null source" {
				input = strings.Replace(input, "        source:\n", "        source: null\n", 1)
			}
			if tc.name == "missing locator" {
				input = strings.Replace(input, tc.old, tc.replacement, 1)
			}
			if tc.name == "missing reason" {
				input = strings.Replace(base, tc.old, tc.replacement, 1)
			}
			_, err := data.ParseProfiles([]byte(input))
			if err == nil {
				t.Fatal("expected rejection")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Fatalf("wrong rejection: %v; want %q", err, tc.want)
			}
		})
	}
}

func TestD07FixtureDoesNotMutateEmbeddedAsset(t *testing.T) {
	p, err := data.ParseProfiles(readFixture(t, "d07-legacy-pointer.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p.Frameworks[0].FieldGroups["http"].Source.ID = "mutated"
	embedded, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(embedded.Frameworks) != 4 || embedded.Frameworks[0].ID != "covenant" || embedded.Frameworks[0].FieldGroups["http"].Source.ID != "v11a-covenant-http-legacy-code" || embedded.Frameworks[1].ID != "merlin" || embedded.Frameworks[1].FieldGroups["http"].Source.ID != "v11a-merlin-http-legacy-code" || embedded.Frameworks[2].ID != "poshc2" || embedded.Frameworks[2].FieldGroups["http"].Source.ID != "v11a-poshc2-http-legacy-code" || embedded.Frameworks[3].ID != "cobaltstrike" {
		t.Fatal("test fixture affected production embedded asset")
	}
}

func TestHeaderExactAuthorizationIsNotRegistered(t *testing.T) {
	asset, err := os.ReadFile("framework-fingerprints.yaml")
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Replace(string(asset), "kind: header_prefix", "kind: header_exact", 1)
	if input == string(asset) {
		t.Fatal("fixture mutation did not apply")
	}
	_, err = data.ParseProfiles([]byte(input))
	if err == nil || !strings.Contains(err.Error(), "header_exact supports only") {
		t.Fatalf("expected precise exact-authorization grammar refusal, got %v", err)
	}
}

func TestPoshKindsStrictGrammar(t *testing.T) {
	asset, err := os.ReadFile("framework-fingerprints.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, old, replacement string }{
		{"cookie wrong direction", "kind: cookie_prefix", "kind: cookie_prefix\\n            message: response"},
		{"cookie wrong header", "header: cookie", "header: authorization"},
		{"raw server request direction", "kind: response_server_raw_exact", "kind: response_server_raw_exact\\n            message: request"},
		{"raw header wrong direction", "kind: response_proto_and_raw_header_name", "kind: response_proto_and_raw_header_name\\n            message: request"},
		{"raw header missing value", "header: Content-type", "header: ''"},
		{"body wrong direction", "kind: body_contains", "kind: body_contains\\n            message: request"},
		{"body has header", "kind: body_contains", "kind: body_contains\\n            header: server"},
		{"empty body marker", "value: IIS ASP.NET 2.0.43451 Server", "value: ''"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.Replace(string(asset), tc.old, tc.replacement, 1)
			if input == string(asset) {
				t.Fatal("mutation did not apply")
			}
			if _, err := data.ParseProfiles([]byte(input)); err == nil {
				t.Fatal("invalid Posh matcher shape accepted")
			}
		})
	}
}
