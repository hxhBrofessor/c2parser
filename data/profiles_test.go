package data_test

import (
	"os"
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

func TestEmbeddedEmptyAssetAndFreshCopies(t *testing.T) {
	first, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	if first.SchemaVersion != 1 || first.Frameworks == nil || len(first.Frameworks) != 0 {
		t.Fatalf("unexpected embedded profile document: %#v", first)
	}
	first.Frameworks = append(first.Frameworks, data.Framework{ID: "caller_mutation"})
	second, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Frameworks) != 0 {
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
	if len(embedded.Frameworks) != 0 {
		t.Fatal("test fixture affected production embedded asset")
	}
}
