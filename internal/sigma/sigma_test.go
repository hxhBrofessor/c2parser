package sigma

import (
	"os"
	"path/filepath"
	"testing"
)

func mustRule(t *testing.T, y string) *Rule {
	t.Helper()
	r, reason, err := Parse([]byte(y), "inline.yml")
	if err != nil || reason != "" {
		t.Fatalf("parse: %v %s", err, reason)
	}
	return r
}

const hdr = "title: t\nid: x\nlevel: high\nlogsource:\n    category: proxy\n"

func TestModifiersAndConditions(t *testing.T) {
	cases := []struct {
		name string
		det  string
		ev   Event
		want bool
	}{
		{"contains|all", "    sel:\n        c-uri|contains|all: ['/a', 'b=']\n    condition: sel", Event{"c-uri": {"/a/x?b=1"}}, true},
		{"contains|all miss", "    sel:\n        c-uri|contains|all: ['/a', 'zz']\n    condition: sel", Event{"c-uri": {"/a/x?b=1"}}, false},
		{"case-insensitive eq", "    sel:\n        cs-method: post\n    condition: sel", Event{"cs-method": {"POST"}}, true},
		{"cased", "    sel:\n        cs-method|cased: post\n    condition: sel", Event{"cs-method": {"POST"}}, false},
		{"endswith list", "    sel:\n        cs-host|endswith: ['.ru', '.su']\n    condition: sel", Event{"cs-host": {"evil.su"}}, true},
		{"wildcard", "    sel:\n        c-useragent: 'Internet Explorer *'\n    condition: sel", Event{"c-useragent": {"Internet Explorer 6.0"}}, true},
		{"escaped star is literal", "    sel:\n        path: '\\\\\\*\\IPC$'\n    condition: sel", Event{"path": {`\\HOST\IPC$`}}, false},
		{"escaped star literal hit", "    sel:\n        path: '\\\\\\*\\IPC$'\n    condition: sel", Event{"path": {`\*\IPC$`}}, true},
		{"unescaped wildcard", "    sel:\n        path: '\\\\*\\IPC$'\n    condition: sel", Event{"path": {`\\HOST\IPC$`}}, true},
		{"1 of sel*", "    sel_a:\n        a: 1\n    sel_b:\n        b: 2\n    condition: 1 of sel_*", Event{"b": {"2"}}, true},
		{"all of sel*", "    sel_a:\n        a: 1\n    sel_b:\n        b: 2\n    condition: all of sel_*", Event{"b": {"2"}}, false},
		{"and not filter", "    sel:\n        a: 1\n    filter:\n        b: 2\n    condition: sel and not filter", Event{"a": {"1"}, "b": {"2"}}, false},
		{"parens", "    s1:\n        a: 1\n    s2:\n        b: 2\n    s3:\n        c: 3\n    condition: s1 and (s2 or s3)", Event{"a": {"1"}, "c": {"3"}}, true},
		{"keywords substring", "    sel:\n        path: x\n    kw:\n        - samr\n        - lsarpc\n    condition: sel and not kw", Event{"path": {"x"}, "name": {"\\pipe\\samr"}}, false},
		{"null", "    sel:\n        cs-referrer: null\n    condition: sel", Event{"cs-method": {"GET"}}, true},
		{"cidr", "    sel:\n        dst_ip|cidr: '10.0.0.0/8'\n    condition: sel", Event{"dst_ip": {"10.2.3.4"}}, true},
		{"re", "    sel:\n        query|re: '^[a-z0-9]{30,}\\.'\n    condition: sel", Event{"query": {"abcdefghijabcdefghijabcdefghij12.x.com"}}, true},
		{"base64offset", "    sel:\n        c-uri|base64offset|contains: 'whoami'\n    condition: sel", Event{"c-uri": {"/x?" + "d2hvYW1p"}}, true},
		{"them", "    a:\n        x: 1\n    b:\n        y: 2\n    condition: all of them", Event{"x": {"1"}, "y": {"2"}}, true},
		{"multi-value any", "    sel:\n        c-uri: '/s/ref'\n    condition: sel", Event{"c-uri": {"/s/ref", "http://h/s/ref"}}, true},
		{"gt", "    sel:\n        cs-bytes|gt: 1000\n    condition: sel", Event{"cs-bytes": {"2048"}}, true},
		{"condition list OR", "    a:\n        x: 1\n    b:\n        y: 2\n    condition:\n        - a\n        - b", Event{"y": {"2"}}, true},
	}
	for _, c := range cases {
		r := mustRule(t, hdr+"detection:\n"+c.det+"\n")
		if got := r.Match(c.ev); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestUnsupportedReported(t *testing.T) {
	_, reason, _ := Parse([]byte("title: t\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n    s:\n        Image: x\n    condition: s\n"), "f")
	if reason == "" {
		t.Error("windows process_creation should be unsupported")
	}
	_, _, err := Parse([]byte(hdr+"detection:\n    s:\n        a: 1\n    condition: s | count() > 5\n"), "f")
	if err == nil {
		t.Error("aggregation should error")
	}
}

// Against the real SigmaHQ corpus when available (SIGMA_RULES=path/to/sigma).
func TestRealRules(t *testing.T) {
	dir := os.Getenv("SIGMA_RULES")
	if dir == "" {
		t.Skip("SIGMA_RULES not set")
	}
	load := func(rel string) *Rule {
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Skip(err)
		}
		r, reason, err := Parse(b, rel)
		if err != nil || reason != "" {
			t.Fatalf("%s: %v %s", rel, err, reason)
		}
		return r
	}
	havoc := Event{"c-useragent": {"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"}}
	if !load("rules/web/proxy_generic/proxy_ua_frameworks.yml").Match(havoc) {
		t.Error("proxy_ua_frameworks should match the Havoc UA")
	}
	cs := load("rules/network/dns/net_dns_mal_cobaltstrike.yml")
	if !cs.Match(Event{"query": {"aaa.stage.12345.evil.com"}}) || cs.Match(Event{"query": {"www.google.com"}}) {
		t.Error("net_dns_mal_cobaltstrike")
	}
	x := load("rules/network/zeek/zeek_default_cobalt_strike_certificate.yml")
	if !x.Match(Event{"certificate.serial": {"8BB00EE"}}) {
		t.Error("zeek CS certificate serial")
	}
	if !load("rules/network/zeek/zeek_dce_rpc_mitre_bzar_execution.yml").Match(Event{"endpoint": {"svcctl"}, "operation": {"CreateServiceW"}}) {
		t.Error("BZAR execution svcctl CreateServiceW")
	}
}
