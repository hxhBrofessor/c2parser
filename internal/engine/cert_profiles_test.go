package engine

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"testing"

	"c2parser/data"
)

// Frozen oracle: independently transcribed from the pinned v11a table and
// switch. It intentionally does not read the production YAML or registry.
type frozenCertRow struct {
	framework, kind, value, feature string
	values                          []string
}

var frozenCertRows = []frozenCertRow{
	{"cobaltstrike", "cert_der_sha256_exact", "87f2085c32b6a2cc709b365f55873e207a9caa10bffecf2fd16d3cf9d94d390c", "Cobalt Strike default team-server certificate", nil},
	{"cobaltstrike", "cert_der_sha256_exact", "56a06a233bd30f693de25ef12cc19e8b2c92d3eb97dd969a2578df084c376478", "Cobalt Strike second widely-seen default certificate", nil},
	{"cobaltstrike", "cert_serial_decimal_exact", "146473198", "Cobalt Strike default team-server certificate (serial 0x8BB00EE)", nil},
	{"cobaltstrike", "cert_dn_contains_folded", "", "Cobalt Strike default certificate DN", []string{"major cobalt strike", "o=cobaltstrike", "advancedpentesting"}},
	{"bruteratel", "cert_der_sha256_exact", "d597d6572c5616573170275d0b5d5e3ab0c06d4a9104bbdbe952c4bcb52118c9", "Brute Ratel C4 certificate (Unit 42 2022 cluster)", nil},
	{"bruteratel", "cert_serial_decimal_exact", "476862511373535319627199034793753459614889484917", "Brute Ratel C4 certificate (Unit 42 2022 cluster)", nil},
}

func knownC2CertV11a(ci *certInfo) (string, bool) {
	if ci == nil {
		return "", false
	}
	if why, ok := map[string]string{
		"87f2085c32b6a2cc709b365f55873e207a9caa10bffecf2fd16d3cf9d94d390c": "Cobalt Strike default team-server certificate",
		"56a06a233bd30f693de25ef12cc19e8b2c92d3eb97dd969a2578df084c376478": "Cobalt Strike second widely-seen default certificate",
		"d597d6572c5616573170275d0b5d5e3ab0c06d4a9104bbdbe952c4bcb52118c9": "Brute Ratel C4 certificate (Unit 42 2022 cluster)",
	}[strings.ToLower(ci.SHA256)]; ok {
		return why, true
	}
	if why, ok := map[string]string{
		"146473198": "Cobalt Strike default team-server certificate (serial 0x8BB00EE)",
		"476862511373535319627199034793753459614889484917": "Brute Ratel C4 certificate (Unit 42 2022 cluster)",
	}[ci.Serial]; ok {
		return why, true
	}
	dn := strings.ToLower(ci.Subject + " " + ci.Issuer)
	if strings.Contains(dn, "major cobalt strike") || strings.Contains(dn, "o=cobaltstrike") || strings.Contains(dn, "advancedpentesting") {
		return "Cobalt Strike default certificate DN", true
	}
	c := ci.cert
	if c == nil {
		return "", false
	}
	cn, org, ou := c.Subject.CommonName, firstOr(c.Subject.Organization), firstOr(c.Subject.OrganizationalUnit)
	switch {
	case cn == "P18055077" || org == "Pajfds" && ou == "Jethpro":
		return "PoshC2 default certificate (CN=P18055077, O=Pajfds)", true
	case cn == "Covenant" && ci.SelfSigned:
		return "Covenant default admin certificate (self-signed CN=Covenant)", true
	case org == "Microsoft" && ou == "Security" && cn == "localhost":
		return "Brute Ratel C4 certificate DN (O=Microsoft, OU=Security, CN=localhost)", true
	case c.Issuer.CommonName == "operators" && cn == "multiplayer":
		return "Sliver multiplayer operator certificate (issuer CN=operators)", true
	}
	return "", false
}

func TestCertificateProfilesMatchIndependentFrozenTable(t *testing.T) {
	p, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	registered, err := registeredFrameworkCertItems(p)
	if err != nil {
		t.Fatal(err)
	}
	var got []frozenCertRow
	for _, fw := range []string{"cobaltstrike", "bruteratel"} {
		for _, item := range registered[fw+"/cert"] {
			got = append(got, frozenCertRow{fw, item.Kind, item.Value, item.Feature, append([]string(nil), item.Values...)})
		}
	}
	if !reflect.DeepEqual(got, frozenCertRows) {
		t.Fatalf("certificate profile drift\ngot: %#v\nwant: %#v", got, frozenCertRows)
	}
}

func TestCertificateWholeFunctionDifferential30K(t *testing.T) {
	const seed int64 = 0x5a17c3
	r := rand.New(rand.NewSource(seed))
	positives := []*certInfo{
		{SHA256: frozenCertRows[0].value}, {SHA256: frozenCertRows[1].value}, {SHA256: frozenCertRows[4].value},
		{Serial: frozenCertRows[2].value}, {Serial: frozenCertRows[5].value},
		{Subject: "MAJOR COBALT STRIKE"}, {Subject: "O=COBALTSTRIKE"}, {Issuer: "AdvancedPenTesting"},
		{cert: &x509.Certificate{Subject: pkixName("P18055077")}},
		{cert: &x509.Certificate{Subject: pkixOrgOU("Pajfds", "Jethpro")}},
		{SelfSigned: true, cert: &x509.Certificate{Subject: pkixName("Covenant")}},
		{cert: &x509.Certificate{Subject: pkixOrgOUCN("Microsoft", "Security", "localhost")}},
		{cert: &x509.Certificate{Subject: pkixName("multiplayer"), Issuer: pkixName("operators")}},
	}
	for i, ci := range positives {
		want := []string{
			frozenCertRows[0].feature, frozenCertRows[1].feature, frozenCertRows[4].feature,
			frozenCertRows[2].feature, frozenCertRows[5].feature,
			frozenCertRows[3].feature, frozenCertRows[3].feature, frozenCertRows[3].feature,
			"PoshC2 default certificate (CN=P18055077, O=Pajfds)",
			"PoshC2 default certificate (CN=P18055077, O=Pajfds)",
			"Covenant default admin certificate (self-signed CN=Covenant)",
			"Brute Ratel C4 certificate DN (O=Microsoft, OU=Security, CN=localhost)",
			"Sliver multiplayer operator certificate (issuer CN=operators)",
		}
		if reason, ok := knownC2CertV11a(ci); !ok || reason != want[i] {
			t.Fatalf("forced positive branch %d not reached", i)
		}
	}
	cases := append([]*certInfo{nil, {SHA256: "bad", Serial: "001", Subject: "none"}}, positives...)
	// Explicit precedence combinations: hash before serial/DN, serial before DN, DN before structured.
	cases = append(cases,
		&certInfo{SHA256: frozenCertRows[0].value, Serial: frozenCertRows[2].value, Subject: "major cobalt strike"},
		&certInfo{Serial: frozenCertRows[2].value, Subject: "o=cobaltstrike", cert: &x509.Certificate{Subject: pkixName("P18055077")}},
		&certInfo{Subject: "advancedpentesting", cert: &x509.Certificate{Subject: pkixName("P18055077")}},
	)
	for i := 0; i < 30000; i++ {
		var ci *certInfo
		if i < len(cases) {
			ci = cases[i]
		} else {
			ci = &certInfo{SHA256: randomCertString(r), Serial: randomCertString(r), Subject: randomCertString(r), Issuer: randomCertString(r), SelfSigned: r.Intn(2) == 0}
			if r.Intn(3) != 0 {
				ci.cert = &x509.Certificate{Subject: pkixRandom(r), Issuer: pkixRandom(r)}
			}
		}
		want, wok := knownC2CertV11a(ci)
		got, gok := knownC2Cert(ci)
		if got != want || gok != wok {
			t.Fatalf("seed=%d case=%d got=(%q,%v) want=(%q,%v)", seed, i, got, gok, want, wok)
		}
	}
	// Force each overlap edge explicitly and assert the exact historical tier winner.
	for i, tc := range []struct {
		ci   *certInfo
		want string
	}{
		{&certInfo{SHA256: frozenCertRows[0].value, Serial: frozenCertRows[2].value, Subject: "major cobalt strike"}, frozenCertRows[0].feature},
		{&certInfo{SHA256: frozenCertRows[0].value, Subject: "major cobalt strike"}, frozenCertRows[0].feature},
		{&certInfo{Serial: frozenCertRows[2].value, Subject: "major cobalt strike"}, frozenCertRows[2].feature},
		{&certInfo{Subject: "major cobalt strike", cert: &x509.Certificate{Subject: pkixName("P18055077")}}, frozenCertRows[3].feature},
		{&certInfo{SHA256: frozenCertRows[4].value, Serial: frozenCertRows[2].value}, frozenCertRows[4].feature},
	} {
		got, ok := knownC2Cert(tc.ci)
		if !ok || got != tc.want {
			t.Fatalf("overlap %d got=%q,%v want=%q", i, got, ok, tc.want)
		}
	}
	t.Logf("seed=%d cases=30000 forced_positive_rows=13 sha=3 serial=2 dn_alternatives=3 structured_branches=4 overlap_edges=5 nil_cases=2 divergences=0", seed)
}

func randomCertString(r *rand.Rand) string {
	const chars = "abcdef0123456789XYZ"
	n := r.Intn(90)
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[r.Intn(len(chars))]
	}
	return string(b)
}
func pkixName(cn string) pkix.Name { return pkix.Name{CommonName: cn} }
func pkixOrgOU(org, ou string) pkix.Name {
	return pkix.Name{Organization: []string{org}, OrganizationalUnit: []string{ou}}
}
func pkixOrgOUCN(org, ou, cn string) pkix.Name {
	return pkix.Name{Organization: []string{org}, OrganizationalUnit: []string{ou}, CommonName: cn}
}
func pkixRandom(r *rand.Rand) pkix.Name {
	return pkix.Name{CommonName: randomCertString(r), Organization: []string{randomCertString(r)}, OrganizationalUnit: []string{randomCertString(r)}}
}

func TestCertificateProfileSemanticMutationsKilled(t *testing.T) {
	raw, err := os.ReadFile("../../data/framework-fingerprints.yaml")
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name, from, to string
		mustParse      bool
	}{
		{"SHA value", frozenCertRows[0].value, strings.Repeat("a", 64), true},
		{"serial value", frozenCertRows[2].value, "146473199", true},
		{"DN value", "major cobalt strike", "major cobalt strikx", true},
		{"feature reason", frozenCertRows[0].feature, "Cobalt Strike altered reason", true},
		{"identity row", "cobaltstrike-cert-der-sha256-default", "cobaltstrike-cert-der-sha256-mutated", true},
		{"uppercase SHA", frozenCertRows[0].value, strings.ToUpper(frozenCertRows[0].value), false},
		{"zero serial", "value: \"146473198\"", "value: \"0\"", false},
		{"leading-zero serial", "value: \"146473198\"", "value: \"0146473198\"", false},
		{"duplicate DN", "values: [major cobalt strike, o=cobaltstrike, advancedpentesting]", "values: [major cobalt strike, major cobalt strike, advancedpentesting]", false},
		{"forbidden cert weight", "kind: cert_serial_decimal_exact\n            value:", "kind: cert_serial_decimal_exact\n            weight: 0.4\n            value:", false},
		{"wrong source revision", "citation: Pinned v11a certificate identity lookup code; legacy-code provenance only, external corroboration pending.\n          revision: 425897e8c36005e001e6f6254ede16117194f9d2", "citation: Pinned v11a certificate identity lookup code; legacy-code provenance only, external corroboration pending.\n          revision: 425897e8c36005e001e6f6254ede16117194f9d3", false},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			text := string(raw)
			if !strings.Contains(text, tc.from) {
				t.Fatal("mutation anchor missing")
			}
			candidate := []byte(strings.Replace(text, tc.from, tc.to, 1))
			p, e := data.ParseProfiles(candidate)
			if (e == nil) != tc.mustParse {
				t.Fatalf("parse validity mismatch: %v", e)
			}
			if e == nil {
				registered, re := registeredFrameworkCertItems(p)
				if re == nil && reflect.DeepEqual(certificateRowsForTest(registered), frozenCertRows) {
					t.Fatal("registered frozen identity mutation accepted")
				}
			}
		})
	}
}

func TestCertificateSchemaAndRegistryStructuralRejections(t *testing.T) {
	raw, err := os.ReadFile("../../data/framework-fingerprints.yaml")
	if err != nil {
		t.Fatal(err)
	}
	const csStart = "  - id: cobaltstrike\n"
	const brStart = "  - id: bruteratel\n"
	cases := []struct{ name, from, to string }{
		{"short SHA", frozenCertRows[0].value, strings.Repeat("a", 63)},
		{"nonhex SHA", frozenCertRows[0].value, strings.Repeat("g", 64)},
		{"negative serial", `value: "146473198"`, `value: "-1"`},
		{"empty DN literal", "values: [major cobalt strike, o=cobaltstrike, advancedpentesting]", "values: [\"\", o=cobaltstrike, advancedpentesting]"},
		{"uppercase DN", "values: [major cobalt strike, o=cobaltstrike, advancedpentesting]", "values: [Major Cobalt Strike, o=cobaltstrike, advancedpentesting]"},
		{"unknown key", "kind: cert_der_sha256_exact\n            value:", "kind: cert_der_sha256_exact\n            extra_predicate: x\n            value:"},
		{"wrong value type", "kind: cert_der_sha256_exact\n            value: ", "kind: cert_der_sha256_exact\n            value: ["},
		{"missing value", "            value: 87f2085c32b6a2cc709b365f55873e207a9caa10bffecf2fd16d3cf9d94d390c\n", ""},
		{"forbidden scoring weight", "kind: cert_serial_decimal_exact\n            value:", "kind: cert_serial_decimal_exact\n            weight: 0.2\n            value:"},
		{"wrong certificate group", "      cert:\n        evidence: UNKNOWN\n        verify: false", "      dns:\n        evidence: UNKNOWN\n        verify: false"},
		{"unknown certificate kind", "kind: cert_der_sha256_exact", "kind: cert_expression"},
	}
	start := strings.Index(string(raw), csStart)
	endRel := strings.Index(string(raw)[start+len(csStart):], brStart)
	if start < 0 || endRel < 0 {
		t.Fatal("certificate YAML blocks not found")
	}
	end := start + len(csStart) + endRel
	cs, rest := string(raw)[start:end], string(raw)[end:]
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(cs, tc.from) {
				t.Fatal("mutation anchor missing")
			}
			candidate := []byte(string(raw[:start]) + strings.Replace(cs, tc.from, tc.to, 1) + rest)
			if _, err := data.ParseProfiles(candidate); err == nil {
				t.Fatal("malformed certificate structure accepted")
			}
		})
	}
	for _, tc := range []struct{ name, mutate string }{
		{"wrong item count", "count"}, {"wrong item order", "order"}, {"missing group source", "source"}, {"wrong framework group", "group"}, {"pending populated group", "pending"}, {"duplicate cross-framework debt", "debt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := data.Load()
			if err != nil {
				t.Fatal(err)
			}
			switch tc.mutate {
			case "count":
				g := p.Frameworks[4].FieldGroups["cert"]
				g.Items = g.Items[:1]
				p.Frameworks[4].FieldGroups["cert"] = g
			case "order":
				g := p.Frameworks[3].FieldGroups["cert"]
				g.Items[0], g.Items[1] = g.Items[1], g.Items[0]
				p.Frameworks[3].FieldGroups["cert"] = g
			case "source":
				g := p.Frameworks[3].FieldGroups["cert"]
				g.Source = nil
				p.Frameworks[3].FieldGroups["cert"] = g
			case "group":
				p.Frameworks[4].ID = "poshc2"
			case "pending":
				g := p.Frameworks[3].FieldGroups["cert"]
				g.Verify = true
				p.Frameworks[3].FieldGroups["cert"] = g
			case "debt":
				g := p.Frameworks[4].FieldGroups["cert"]
				g.Items[0].DebtID = "B33-D07-CS-CERT-001"
				p.Frameworks[4].FieldGroups["cert"] = g
			}
			if _, err := registeredFrameworkCertItems(p); err == nil {
				t.Fatal("structural registry mutation accepted")
			}
		})
	}
}

func certificateRowsForTest(registered map[string][]data.Item) []frozenCertRow {
	var out []frozenCertRow
	for _, fw := range []string{"cobaltstrike", "bruteratel"} {
		for _, item := range registered[fw+"/cert"] {
			out = append(out, frozenCertRow{fw, item.Kind, item.Value, item.Feature, append([]string(nil), item.Values...)})
		}
	}
	return out
}

func TestCertificateLookupTiersPreserveNilCertificateAndPriority(t *testing.T) {
	if _, ok := knownC2Cert(nil); ok {
		t.Fatal("nil certInfo matched")
	}
	if _, ok := knownC2Cert(&certInfo{}); ok {
		t.Fatal("empty certInfo matched")
	}
	ci := &certInfo{SHA256: strings.ToUpper(frozenCertRows[0].value), Serial: frozenCertRows[2].value, Subject: "major cobalt strike"}
	if got, ok := knownC2Cert(ci); !ok || got != frozenCertRows[0].feature {
		t.Fatalf("SHA tier priority: %q %v", got, ok)
	}
	ci = &certInfo{Serial: frozenCertRows[2].value, Subject: "major cobalt strike"}
	if got, ok := knownC2Cert(ci); !ok || got != frozenCertRows[2].feature {
		t.Fatalf("serial tier priority: %q %v", got, ok)
	}
}

func TestCertificateD07CrosswalkIsSixItemsAndFourGoBranches(t *testing.T) {
	read := func(name string) map[string]any {
		raw, err := readBoundedEvidenceJSON("../../evidence/" + name)
		if err != nil {
			t.Fatal(err)
		}
		m, err := parseStrictEvidenceJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	debt, source := read("certificate-debt-register.json"), read("certificate-predicate-source-map.json")
	if stringField(debt, "source_commit") != b34V11aSource || stringField(source, "source_commit") != b34V11aSource || stringField(debt, "external_provenance") != "PENDING" || stringField(source, "external_provenance") != "PENDING" {
		t.Fatal("certificate provenance root binding mismatch")
	}
	debtRows, err := evidenceRows(debt, "items")
	if err != nil {
		t.Fatal(err)
	}
	sourceRows, err := evidenceRows(source, "ordered_predicates")
	if err != nil {
		t.Fatal(err)
	}
	retained, err := evidenceRows(debt, "go_retained")
	if err != nil {
		t.Fatal(err)
	}
	retainedSource, err := evidenceRows(source, "go_retained")
	if err != nil {
		t.Fatal(err)
	}
	if len(debtRows) != 6 || len(sourceRows) != 6 || len(retained) != 4 || len(retainedSource) != 4 {
		t.Fatalf("bad D-07 cardinality debt=%d source=%d go=%d/%d", len(debtRows), len(sourceRows), len(retained), len(retainedSource))
	}
	p, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	registered, err := registeredFrameworkCertItems(p)
	if err != nil {
		t.Fatal(err)
	}
	var items []data.Item
	for _, fw := range []string{"cobaltstrike", "bruteratel"} {
		items = append(items, registered[fw+"/cert"]...)
	}
	for i, item := range items {
		d, s := debtRows[i], sourceRows[i]
		commit, path, lines, ok := parseV11aLocator(item.Locator)
		sourceCommit := stringField(s, "source_commit")
		if sourceCommit == "" {
			sourceCommit = stringField(source, "source_commit")
		}
		if !ok || stringField(d, "id") != item.ID || stringField(s, "id") != item.ID || stringField(d, "debt_id") != item.DebtID || stringField(s, "debt_id") != item.DebtID || stringField(d, "source_commit") != commit || sourceCommit != commit || stringField(d, "source_path") != path || stringField(s, "source_path") != path || stringField(d, "source_lines") != lines || stringField(s, "source_lines") != lines || stringField(d, "legacy_reason") != item.Feature || stringField(s, "legacy_reason") != item.Feature || stringField(s, "kind") != item.Kind || !strings.Contains(strings.ToLower(stringField(d, "provenance")), "external provenance pending") {
			t.Fatalf("D-07 mismatch at %s", item.ID)
		}
	}
	want := []string{"poshc2", "covenant", "bruteratel_c4", "sliver"}
	for i := range want {
		if stringField(retained[i], "branch") != want[i] || stringField(retained[i], "status") != "GO_RETAINED" || stringField(retainedSource[i], "branch") != want[i] || stringField(retainedSource[i], "status") != "GO_RETAINED" {
			t.Fatalf("structured branch record %d mismatch", i)
		}
	}
}
