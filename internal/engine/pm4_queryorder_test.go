package engine

import (
	"reflect"
	"testing"
)

// PM-4 follow-up: url.ParseQuery returns a map, so requestTokens must impose a
// deterministic (sorted-key) order on query carrier tokens. Reversing the
// parameter order on the wire must yield identical request tokens — and hence
// identical findings — rather than depending on Go's randomised map range.
func TestPM4QueryParamOrderDeterministic(t *testing.T) {
	a := "QUFBQUFBQUFBQUFBQUFBQUFB" // >= minTokenLen, base64-ish
	b := "QkJCQkJCQkJCQkJCQkJCQkJC" // >= minTokenLen
	fwd := &httpMsg{req: true, uri: "/p?alpha=" + a + "&bravo=" + b}
	rev := &httpMsg{req: true, uri: "/p?bravo=" + b + "&alpha=" + a}
	tf, tr := requestTokens(fwd), requestTokens(rev)
	if !reflect.DeepEqual(tf, tr) {
		t.Fatalf("query token order depends on wire order:\n forward=%#v\n reverse=%#v", tf, tr)
	}
	// And the order is the sorted-key order, run after run (map range is random).
	want := []token{{"query:alpha", a}, {"query:bravo", b}}
	for i := 0; i < 64; i++ {
		if got := requestTokens(fwd); !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d: tokens %#v, want sorted %#v", i, got, want)
		}
	}
}
