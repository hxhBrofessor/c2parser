package engine

import (
	"reflect"
	"sort"
	"testing"

	"c2parser/data"
)

// frozenCovenantHTTP is the v11a Covenant HTTP predicate table at
// repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:103-113,156-160.
// It is an independent oracle: it must never be generated from the YAML asset.
// Any change to a migrated Covenant HTTP item must fail this test.
var frozenCovenantHTTP = []frozenItem{
	{"uri_exact", "request", "", "/en-us/index.html", nil, "URI /en-us/index.html", 0.25},
	{"uri_exact", "request", "", "/en-us/docs.html", nil, "URI /en-us/docs.html", 0.25},
	{"uri_exact", "request", "", "/en-us/test.html", nil, "URI /en-us/test.html", 0.25},
	{"header_exact", "request", "user-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36", nil, "Chrome/41.0.2228.0 User-Agent", 0.45},
	{"header_contains", "request", "cookie", "SESSIONID=1552332971750", nil, "Cookie SESSIONID=1552332971750", 0.9},
	{"body_prefix", "request", "", "i=a19ea23062db990386a3a478cb89d52e&data=", nil, "POST body template i=a19ea23062db…&data=", 0.9},
	{"header_exact", "response", "server", "Microsoft-IIS/7.5", nil, "Server: Microsoft-IIS/7.5", 0.15},
	{"body_contains_any", "response", "", "", []string{"// Hello World! ", "<title>Hello World!</title>"}, "Hello World! response template", 0.4},
}

type frozenItem struct {
	Kind, Message, Header, Value string
	Values                       []string
	Feature                      string
	Weight                       float64
}

func TestCovenantProfileMatchesFrozenV11aTable(t *testing.T) {
	p, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	items, err := covenantHTTPItems(p)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]frozenItem, 0, len(items))
	for _, it := range items {
		got = append(got, frozenItem{it.Kind, it.Message, it.Header, it.Value, it.Values, it.Feature, it.Weight})
	}
	if !reflect.DeepEqual(got, frozenCovenantHTTP) {
		t.Fatalf("migrated Covenant HTTP items differ from the frozen v11a table\n got: %#v\nwant: %#v", got, frozenCovenantHTTP)
	}

	// The frozen table must also agree with the v11a Go oracles that the B-3.1 golden serializes.
	var uris []string
	for _, it := range frozenCovenantHTTP {
		if it.Kind == "uri_exact" {
			uris = append(uris, it.Value)
		}
	}
	var oracle []string
	for u := range covenantURIs {
		oracle = append(oracle, u)
	}
	sort.Strings(uris)
	sort.Strings(oracle)
	if !reflect.DeepEqual(uris, oracle) {
		t.Fatalf("frozen URI set %v differs from covenantURIs %v", uris, oracle)
	}
	if frozenCovenantHTTP[3].Value != covenantUA {
		t.Fatalf("frozen user-agent differs from covenantUA")
	}
}
