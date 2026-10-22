package data

import (
	"fmt"
	"os"
	"reflect"
	"testing"
)

// FuzzParseProfiles checks that ParseProfiles never panics and that every
// accepted document yields a result that re-validates: the schema version,
// framework IDs and field groups pass the same validators ParseProfiles
// applies, and parsing the same input again returns an equal value.
func FuzzParseProfiles(f *testing.F) {
	for _, name := range []string{
		"framework-fingerprints.yaml",
		"testdata/valid-profile.yaml",
		"testdata/d07-legacy-pointer.yaml",
	} {
		b, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		p, err := ParseProfiles(src)
		if err != nil {
			return
		}
		if p.SchemaVersion != 1 {
			t.Fatalf("accepted schema_version %d", p.SchemaVersion)
		}
		ids := make(map[string]bool, len(p.Frameworks))
		for i, fw := range p.Frameworks {
			if !frameworkIDPattern.MatchString(fw.ID) || ids[fw.ID] {
				t.Fatalf("frameworks[%d]: accepted invalid or duplicate ID %q", i, fw.ID)
			}
			ids[fw.ID] = true
			for group, g := range fw.FieldGroups {
				path := fmt.Sprintf("frameworks[%d].field_groups.%s", i, group)
				if !allowedGroup(group) {
					t.Fatalf("%s: accepted unknown field group", path)
				}
				if err := validateGroup(path, g); err != nil {
					t.Fatalf("%s: result does not re-validate: %v", path, err)
				}
				if g.Verify && len(g.Items) != 0 {
					t.Fatalf("%s: verify:true group has items", path)
				}
				if err := validateItems(path, fw.ID, group, g.Items); err != nil {
					t.Fatalf("%s: items do not re-validate: %v", path, err)
				}
			}
		}
		again, err := ParseProfiles(src)
		if err != nil {
			t.Fatalf("second parse of accepted input failed: %v", err)
		}
		if !reflect.DeepEqual(p, again) {
			t.Fatal("second parse of accepted input differs")
		}
	})
}
