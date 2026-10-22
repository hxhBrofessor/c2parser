package sigma

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

// WS-5 slice 2 (Q-05 implementation). These tests pin the post-slice-2
// built-in Sigma rule set and guard the kept Havoc rule and rule-file hygiene.
// They are written test-first and fail against the v11.1 tree (which still
// embeds the Sliver and three Mythic rules and carries the hygiene strings).

const builtinDir = "../../rules/sigma"

func loadBuiltin(t *testing.T) []*Rule {
	t.Helper()
	rules, rep := Load(builtinDir)
	if len(rules) == 0 {
		t.Fatalf("no built-in rules loaded: %+v", rep)
	}
	return rules
}

// W5-1/W5-3(M-B): the embedded set is exactly the kept Havoc rule.
func TestWS5BuiltinSetIsKeptIDsOnly(t *testing.T) {
	want := []string{"e1f2bf20-99bc-4774-88ca-cd59024338dc"}
	var got []string
	for _, r := range loadBuiltin(t) {
		got = append(got, r.ID)
	}
	sort.Strings(got)
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("built-in rule id set = %v, want %v", got, want)
	}
}

// W5-1: the retired Sliver signal id must not be present in the embedded set.
func TestWS5RetiredSliverSignalAbsent(t *testing.T) {
	for _, r := range loadBuiltin(t) {
		if len(r.ID) >= 8 && r.ID[:8] == "50995159" {
			t.Fatalf("retired rule id %s is still embedded (%s)", r.ID, r.File)
		}
	}
}

// F4: the kept Havoc rule fires on a synthetic request with the default UA,
// POST and the literal */* content type, and one-field-off near misses do not.
func TestWS5HavocRuleFiresAndNearMisses(t *testing.T) {
	var havoc *Rule
	for _, r := range loadBuiltin(t) {
		if len(r.ID) >= 8 && r.ID[:8] == "e1f2bf20" {
			havoc = r
		}
	}
	if havoc == nil {
		t.Fatal("Havoc rule e1f2bf20 not found in built-in set")
	}
	const ua = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
	hit := Event{"cs-method": {"POST"}, "c-useragent": {ua}, "cs-content-type": {"*/*"}}
	if !havoc.Match(hit) {
		t.Errorf("Havoc rule did not fire on the default POST + UA + */* request")
	}
	misses := []struct {
		name string
		ev   Event
	}{
		{"GET not POST", Event{"cs-method": {"GET"}, "c-useragent": {ua}, "cs-content-type": {"*/*"}}},
		{"different UA", Event{"cs-method": {"POST"}, "c-useragent": {"curl/8.4.0"}, "cs-content-type": {"*/*"}}},
		{"content-type octet-stream", Event{"cs-method": {"POST"}, "c-useragent": {ua}, "cs-content-type": {"application/octet-stream"}}},
	}
	for _, m := range misses {
		if havoc.Match(m.ev) {
			t.Errorf("Havoc rule fired on near miss %q (should not)", m.name)
		}
	}
}

// F1/F5/W5-4: no embedded rule file carries a hygiene-denylisted string in its
// description or references. Patterns are shape-based and held here; on failure
// only the file path and the pattern index are reported, never the matched text.
func TestWS5EmbeddedRuleHygiene(t *testing.T) {
	denylist := []*regexp.Regexp{
		// military unit designator shape, e.g. "<ordinal> CY BN"
		regexp.MustCompile(`(?i)\b\d{1,4}(?:st|nd|rd|th)\s+(?:CY|CYBER|MI|IN|BN|BDE|CO|SB|EN)\b`),
		// person-name citation shape, e.g. "observed by Name (2024)"
		regexp.MustCompile(`(?i)\bobserved by\s+[A-Z][a-z]+\s*\(\d{4}\)`),
		// tracking parameters in URLs
		regexp.MustCompile(`utm_[a-z]+=`),
	}
	// S2-2: scan both the embedded built-in rules and the public, non-embedded
	// docs/sigma-examples/ (just as public a surface).
	dirs := []string{builtinDir, "../../docs/sigma-examples"}
	for _, dir := range dirs {
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range ents {
			if e.IsDir() || filepath.Ext(e.Name()) != ".yml" {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatalf("read %s/%s: %v", dir, e.Name(), err)
			}
			for i, re := range denylist {
				if re.Match(b) {
					t.Errorf("rule %s/%s matches hygiene denylist pattern #%d (text withheld)", dir, e.Name(), i)
				}
			}
		}
	}
}
