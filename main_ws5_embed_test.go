package main

import (
	"sort"
	"testing"

	"c2parser/internal/sigma"
)

// WS-5 S2a / S2-3: assert the built-in rule ids loaded from the *embedded* FS
// the CLI actually uses (go:embed rules/sigma/*.yml) are exactly {e1f2bf20}.
// This guards against the embed glob and the on-disk directory drifting apart
// (the internal/sigma test loads the directory from disk).
func TestWS5EmbeddedBuiltinSetIsKeptIDsOnly(t *testing.T) {
	sub, err := fsSub(builtinRules, "rules/sigma")
	if err != nil {
		t.Fatalf("fsSub: %v", err)
	}
	rules, rep := sigma.LoadFS(sub, "builtin")
	if len(rules) == 0 {
		t.Fatalf("no embedded built-in rules loaded: %+v", rep)
	}
	var got []string
	for _, r := range rules {
		got = append(got, r.ID)
	}
	sort.Strings(got)
	want := []string{"e1f2bf20-99bc-4774-88ca-cd59024338dc"}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("embedded built-in rule id set = %v, want %v", got, want)
	}
}
