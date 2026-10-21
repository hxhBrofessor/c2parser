package engine

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"c2parser/data"
	"c2parser/internal/stats"
)

// csDefaultURIs is retained only for the immutable v11a reference matcher and
// golden tests. Production matching reads the values from the embedded YAML.
var csDefaultURIs = map[string]bool{
	"/ca": true, "/dpixel": true, "/__utm.gif": true, "/pixel.gif": true,
	"/g.pixel": true, "/dot.gif": true, "/updates.rss": true, "/fwlink": true,
	"/cm": true, "/cx": true, "/pixel": true, "/match": true,
	"/visit.js": true, "/load": true, "/push": true, "/ptj": true,
	"/j.ad": true, "/ga.js": true, "/en_US/all.js": true,
	"/activity": true, "/IE9CompatViewList.xml": true,
}

var (
	v11aCookieRE     = regexp.MustCompile(`^[A-Za-z0-9+/]{40,}={0,2}$`)
	v11aSubmitRE     = regexp.MustCompile(`^id=\d+$`)
	v11aStagerRE     = regexp.MustCompile(`^/[A-Za-z0-9]{4}$`)
	v11aCovenantURIs = map[string]bool{"/en-us/index.html": true, "/en-us/docs.html": true, "/en-us/test.html": true}
)

func v11aStagerChecksum(path string) (int, bool) {
	if !v11aStagerRE.MatchString(path) {
		return 0, false
	}
	s := 0
	for i := 1; i < len(path); i++ {
		s += int(path[i])
	}
	s %= 256
	return s, s == 92 || s == 93
}

// This is a test-only literal copy of the complete pinned v11a matcher. It
// neither loads the migrated YAML nor calls the migrated matcher/helpers.
func matchFrameworkDefaultsV11aWholeFunction(ch *httpChannel, m *httpMsg) {
	f := m.frame
	if m.req {
		path, query, _ := strings.Cut(m.uri, "?")
		ua, ck := m.hdr["user-agent"], m.hdr["cookie"]
		ct := strings.TrimSpace(m.hdr["content-type"])
		if v11aCovenantURIs[path] {
			ch.fwAdd("Covenant", "URI "+path, .25, f)
		}
		if ua == "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36" {
			ch.fwAdd("Covenant", "Chrome/41.0.2228.0 User-Agent", .45, f)
		}
		if strings.Contains(ck, "SESSIONID=1552332971750") {
			ch.fwAdd("Covenant", "Cookie SESSIONID=1552332971750", .9, f)
		}
		if bytes.HasPrefix(m.head, []byte("i=a19ea23062db990386a3a478cb89d52e&data=")) {
			ch.fwAdd("Covenant", "POST body template i=a19ea23062db…&data=", .9, f)
		}
		if m.method == "POST" && path == "/" {
			ch.fwAdd("Merlin", "POST /", .1, f)
		}
		if strings.EqualFold(ct, "application/octet-stream; charset=utf-8") {
			ch.fwAdd("Merlin", "Content-Type application/octet-stream; charset=utf-8", .5, f)
		}
		if strings.HasPrefix(m.hdr["authorization"], "Bearer eyJ") {
			ch.fwAdd("Merlin", "Authorization: Bearer <JWT>", .3, f)
		}
		if ua == "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36" {
			ch.fwAdd("Merlin", "Chrome/40.0.2214.85 User-Agent", .55, f)
		}
		if strings.HasPrefix(ck, "SessionID=") {
			ch.fwAdd("PoshC2", "Cookie SessionID=", .3, f)
		}
		if m.method == "GET" && csDefaultURIs[path] && v11aCookieRE.MatchString(ck) {
			ch.fwAdd("Cobalt Strike", "GET default URI "+path+" with bare base64 Cookie metadata", .6, f)
		}
		if m.method == "POST" && path == "/submit.php" && v11aSubmitRE.MatchString(query) {
			s := .55
			if strings.EqualFold(ct, "application/octet-stream") {
				s = .7
			}
			ch.fwAdd("Cobalt Strike", "POST /submit.php?id=<n> (task output)", s, f)
		}
		if m.method == "GET" {
			if sum, ok := v11aStagerChecksum(path); ok {
				ch.fwAdd("Cobalt Strike", fmt.Sprintf("stager URI %s (checksum8 = %d)", path, sum), .35, f)
			}
		}
		return
	}
	sv, ct := m.hdr["server"], strings.TrimSpace(m.hdr["content-type"])
	if sv == "Microsoft-IIS/7.5" {
		ch.fwAdd("Covenant", "Server: Microsoft-IIS/7.5", .15, f)
	}
	if bytes.Contains(m.head, []byte("// Hello World! ")) || bytes.Contains(m.head, []byte("<title>Hello World!</title>")) {
		ch.fwAdd("Covenant", "Hello World! response template", .4, f)
	}
	if m.serverRaw == "Apache " {
		ch.fwAdd("PoshC2", `"Server: Apache " with trailing space`, .6, f)
	}
	if m.proto == "HTTP/1.0" && v11aHasHeaderName(m, "Content-type") {
		ch.fwAdd("PoshC2", "HTTP/1.0 response with lower-case Content-type", .3, f)
	}
	if bytes.Contains(m.head, []byte("IIS ASP.NET 2.0.43451 Server")) {
		ch.fwAdd("PoshC2", "404 footer IIS ASP.NET 2.0.43451", .7, f)
	}
	if bytes.Contains(m.head, []byte("<address>Apache (Debian) Server")) {
		ch.fwAdd("PoshC2", "unversioned Apache (Debian) 404 footer", .5, f)
	}
	if bytes.Contains(m.head, []byte(`slack-app-id" content="#av33f33"`)) {
		ch.fwAdd("PoshC2", "200 page slack-app-id #av33f33", .8, f)
	}
	if m.status == 404 && ct == "text/plain" && m.bodyLen == 0 && m.hdr["content-length"] == "0" {
		ch.fwAdd("Cobalt Strike", "empty text/plain 404", .2, f)
	}
}

func v11aHasHeaderName(m *httpMsg, exact string) bool {
	for _, k := range m.order {
		if k == exact {
			return true
		}
	}
	return false
}

var cobaltFrozen = []data.Item{
	{ID: "cobaltstrike-http-get-default-uri-cookie", DebtID: "B33-D07-CS-HTTP-001", Locator: "repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:43-44", Kind: "get_default_uri_b64_cookie", Message: "request", Method: "GET", Header: "cookie", Values: []string{"/ca", "/dpixel", "/__utm.gif", "/pixel.gif", "/g.pixel", "/dot.gif", "/updates.rss", "/fwlink", "/cm", "/cx", "/pixel", "/match", "/visit.js", "/load", "/push", "/ptj", "/j.ad", "/ga.js", "/en_US/all.js", "/activity", "/IE9CompatViewList.xml"}, Feature: "GET default URI {path} with bare base64 Cookie metadata", Weight: .6, Reason: "Pinned v11a code carry-forward only; external provenance is pending."},
	{ID: "cobaltstrike-http-post-submit-id", DebtID: "B33-D07-CS-HTTP-002", Locator: "repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:139-145", Kind: "post_submit_id", Message: "request", Method: "POST", Header: "content-type", Value: "application/octet-stream", Path: "/submit.php", ElevatedWeight: .7, Feature: "POST /submit.php?id=<n> (task output)", Weight: .55, Reason: "Pinned v11a code carry-forward only; external provenance is pending."},
	{ID: "cobaltstrike-http-get-checksum8-stager", DebtID: "B33-D07-CS-HTTP-003", Locator: "repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:146-150", Kind: "get_checksum8_stager", Message: "request", Method: "GET", Checksums: []int{92, 93}, Feature: "stager URI {path} (checksum8 = {sum})", Weight: .35, Reason: "Pinned v11a code carry-forward only; external provenance is pending."},
	{ID: "cobaltstrike-http-response-empty-404", DebtID: "B33-D07-CS-HTTP-004", Locator: "repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:178-180", Kind: "response_empty_404", Message: "response", Header: "content-type", Value: "text/plain", Status: 404, Feature: "empty text/plain 404", Weight: .2, Reason: "Pinned v11a code carry-forward only; external provenance is pending."},
}

func TestCobaltStrikeFrozenTable(t *testing.T) {
	p, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	registered, err := registeredFrameworkHTTPItems(p)
	if err != nil {
		t.Fatal(err)
	}
	got := registered["cobaltstrike/http"]
	if len(got) != len(cobaltFrozen) {
		t.Fatalf("Cobalt item count %d", len(got))
	}
	for i := range got {
		// The URI list has set semantics; ordering in YAML is not runtime behavior.
		a, b := got[i], cobaltFrozen[i]
		a.Values = nil
		b.Values = nil
		if !reflect.DeepEqual(a, b) {
			t.Errorf("Cobalt item %d differs: got %#v want %#v", i, a, b)
		}
		if i == 0 && !sameStringSet(got[i].Values, cobaltFrozen[i].Values) {
			t.Errorf("default URI set differs")
		}
	}
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}

func TestCobaltFrozenTableKillsSemanticMutations(t *testing.T) {
	original, err := os.ReadFile("../../data/framework-fingerprints.yaml")
	if err != nil {
		t.Fatal(err)
	}
	mutants := []struct{ name, old, new string }{
		{"URI substitution", "/ca, /dpixel", "/zz, /dpixel"},
		{"CS1 weight", "            weight: 0.60", "            weight: 0.61"},
		{"CS2 path", "            path: /submit.php", "            path: /submit.cgi"},
		{"CS2 weight", "            weight: 0.55", "            weight: 0.56"},
		{"CS2 elevated", "            elevated_weight: 0.70", "            elevated_weight: 0.71"},
		{"CS2 content type", "            value: application/octet-stream", "            value: application/octet-streamx"},
		{"CS3 checksum", "            checksums: [92, 93]", "            checksums: [92, 94]"},
		{"CS3 weight", "            weight: 0.35", "            weight: 0.36"},
		{"CS3 template", "            feature: stager URI {path} (checksum8 = {sum})", "            feature: stage URI {path} (checksum8 = {sum})"},
		{"CS4 status", "            status: 404", "            status: 405"},
		{"CS4 value", "            value: text/plain", "            value: text/html"},
		{"CS4 weight", "            weight: 0.20", "            weight: 0.21"},
		{"CS4 feature", "            feature: empty text/plain 404", "            feature: empty text/plain notfound"},
	}
	for _, tc := range mutants {
		t.Run(tc.name, func(t *testing.T) {
			start := bytes.Index(original, []byte("  - id: cobaltstrike\n"))
			if start < 0 {
				t.Fatal("Cobalt section missing")
			}
			mut := append([]byte(nil), original[:start]...)
			mut = append(mut, bytes.Replace(original[start:], []byte(tc.old), []byte(tc.new), 1)...)
			if bytes.Equal(mut, original) {
				t.Fatal("mutator did not apply")
			}
			p, err := data.ParseProfiles(mut)
			if err != nil {
				t.Fatalf("semantic mutant should pass schema: %v", err)
			}
			groups, err := registeredFrameworkHTTPItems(p)
			if err != nil {
				t.Fatalf("metadata registry should allow YAML value change: %v", err)
			}
			got := groups["cobaltstrike/http"]
			if cobaltItemsEqual(got, cobaltFrozen) {
				t.Fatal("frozen oracle did not detect semantic mutant")
			}
		})
	}
}

func cobaltItemsEqual(got, want []data.Item) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		a, b := got[i], want[i]
		if i == 0 {
			if !sameStringSet(a.Values, b.Values) {
				return false
			}
			a.Values = nil
			b.Values = nil
		}
		if !reflect.DeepEqual(a, b) {
			return false
		}
	}
	return true
}

func TestCobaltRuntimeBranchMatrixAndWholeFunctionDifferential30K(t *testing.T) {
	p, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := registeredFrameworkHTTPItems(p)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{covenantHTTP: profiles["covenant/http"], merlinHTTP: profiles["merlin/http"], poshHTTP: profiles["poshc2/http"], cobaltHTTP: profiles["cobaltstrike/http"]}
	var cases [][]*httpMsg
	add := func(msgs ...*httpMsg) { cases = append(cases, msgs) }
	validCookie := strings.Repeat("A", 40)
	for _, uri := range cobaltFrozen[0].Values {
		add(&httpMsg{req: true, method: "GET", uri: uri, hdr: map[string]string{"cookie": validCookie}, frame: int64(len(cases) + 1)})
	}
	for _, n := range []int{39, 40, 41} {
		add(&httpMsg{req: true, method: "GET", uri: "/ca", hdr: map[string]string{"cookie": strings.Repeat("A", n)}, frame: int64(len(cases) + 1)})
	}
	for _, cookie := range []string{strings.Repeat("A", 40) + "=", strings.Repeat("A", 40) + "==", strings.Repeat("A", 40) + "===", strings.Repeat("A", 39) + "!", strings.Repeat("A", 39) + " "} {
		add(&httpMsg{req: true, method: "GET", uri: "/ca", hdr: map[string]string{"cookie": cookie}, frame: int64(len(cases) + 1)})
	}
	add(&httpMsg{req: true, method: "GET", uri: "/ca", hdr: map[string]string{}, frame: int64(len(cases) + 1)})
	add(&httpMsg{req: true, method: "GET", uri: "/ca/", hdr: map[string]string{"cookie": validCookie}, frame: int64(len(cases) + 1)})
	add(&httpMsg{req: true, method: "get", uri: "/ca", hdr: map[string]string{"cookie": validCookie}, frame: int64(len(cases) + 1)})
	for _, q := range []string{"id=1", "id=", "id=1&x", "ID=1", "?id=1", "id=1?x"} {
		add(&httpMsg{req: true, method: "POST", uri: "/submit.php?" + q, hdr: map[string]string{"content-type": "application/octet-stream"}, frame: int64(len(cases) + 1)})
	}
	for _, ct := range []string{"application/octet-stream", " application/octet-stream ", "APPLICATION/OCTET-STREAM", "application/octet-streamx", ""} {
		add(&httpMsg{req: true, method: "POST", uri: "/submit.php?id=8", hdr: map[string]string{"content-type": ct}, frame: int64(len(cases) + 1)})
	}
	for _, tc := range []struct {
		ct   string
		want float64
	}{{"application/octet-stream", .7}, {" application/octet-stream ", .7}, {"APPLICATION/OCTET-STREAM", .7}, {"application/octet-streamx", .55}, {"", .55}} {
		m := &httpMsg{req: true, method: "POST", uri: "/submit.php?id=8", hdr: map[string]string{"content-type": tc.ct}, frame: 901}
		ch := &httpChannel{}
		e.matchFrameworkDefaults(ch, m)
		st := ch.fw["Cobalt Strike"]
		if st == nil || st.feats["POST /submit.php?id=<n> (task output)"] != tc.want || len(st.frames) != 1 {
			t.Fatalf("CS-2 content-type %q got %#v want weight %v and one frame", tc.ct, st, tc.want)
		}
	}
	paths := map[int]string{}
	for x := 0; x < 62 && (paths[91] == "" || paths[92] == "" || paths[93] == "" || paths[94] == ""); x++ {
		for y := 0; y < 62 && (paths[91] == "" || paths[92] == "" || paths[93] == "" || paths[94] == ""); y++ {
			for z := 0; z < 62 && (paths[91] == "" || paths[92] == "" || paths[93] == "" || paths[94] == ""); z++ {
				for w := 0; w < 62; w++ {
					s := "/" + string([]byte{alphaNum[x], alphaNum[y], alphaNum[z], alphaNum[w]})
					sum, ok := checksum8Sum(s)
					if ok && (sum == 91 || sum == 92 || sum == 93 || sum == 94) && paths[sum] == "" {
						paths[sum] = s
					}
				}
			}
		}
	}
	for _, sum := range []int{91, 92, 93, 94} {
		path := paths[sum]
		if path == "" {
			t.Fatalf("source-grounded checksum path missing for %d", sum)
		}
		add(&httpMsg{req: true, method: "GET", uri: path, hdr: map[string]string{}, frame: int64(len(cases) + 1)})
	}
	for _, tc := range []struct {
		status int
		ct, cl string
		body   int64
	}{{404, "text/plain", "0", 0}, {200, "text/plain", "0", 0}, {404, " text/plain ", "0", 0}, {404, "text/plain; charset=utf-8", "0", 0}, {404, "text/plain", "00", 0}, {404, "text/plain", "", 0}, {404, "text/plain", "0", 1}} {
		add(&httpMsg{req: false, status: tc.status, hdr: map[string]string{"content-type": tc.ct, "content-length": tc.cl}, bodyLen: tc.body, frame: int64(len(cases) + 1)})
	}
	// Combine every migrated framework in one channel to verify feature/frame ordering and cap behavior.
	add(&httpMsg{req: true, method: "GET", uri: "/ca", hdr: map[string]string{"cookie": validCookie, "user-agent": covenantUA}, frame: 101}, &httpMsg{req: true, method: "POST", uri: "/submit.php?id=1", hdr: map[string]string{"content-type": "application/octet-stream", "cookie": "SessionID=x", "authorization": "Bearer eyJx"}, frame: 102}, &httpMsg{req: true, method: "POST", uri: "/", hdr: map[string]string{"content-type": "application/octet-stream; charset=utf-8", "user-agent": merlinUA}, frame: 103}, &httpMsg{req: false, status: 404, hdr: map[string]string{"content-type": "text/plain", "content-length": "0", "server": "Microsoft-IIS/7.5"}, head: []byte("<address>Apache (Debian) Server IIS ASP.NET 2.0.43451 Server"), frame: 104})
	// deterministic multi-message random channels; explicit fixtures above ensure all rare positives.
	const seed int64 = 0x4353423333
	rng := rand.New(rand.NewSource(seed))
	choices := []string{"/ca", "/noise", "/submit.php?id=7", "/submit.php?id=", "/pixel.gif", "/AAAA", "/WWWW"}
	for len(cases) < 30000 {
		msgs := make([]*httpMsg, 1+rng.Intn(4))
		for j := range msgs {
			req := rng.Intn(2) == 0
			hdr := map[string]string{"cookie": []string{validCookie, "bad", "SessionID=x"}[rng.Intn(3)], "content-type": []string{"application/octet-stream", " text/plain ", "application/octet-streamx"}[rng.Intn(3)], "content-length": []string{"0", "00", ""}[rng.Intn(3)]}
			msgs[j] = &httpMsg{req: req, method: []string{"GET", "POST", "post", "PUT"}[rng.Intn(4)], uri: choices[rng.Intn(len(choices))], status: []int{200, 404}[rng.Intn(2)], hdr: hdr, bodyLen: int64(rng.Intn(2)), frame: int64(len(cases)*4 + j + 1)}
		}
		add(msgs...)
	}
	counts := map[string]int{}
	for ci, channel := range cases {
		got, want := &httpChannel{}, &httpChannel{}
		for _, m := range channel {
			e.matchFrameworkDefaults(got, m)
			matchFrameworkDefaultsV11aWholeFunction(want, m)
		}
		if !reflect.DeepEqual(got.fw, want.fw) {
			t.Fatalf("seed=%d case=%d current=%#v legacy=%#v", seed, ci, got.fw, want.fw)
		}
		gotAcc, wantAcc := &acc{f: &Finding{}, sigs: map[string]stats.Signal{}}, &acc{f: &Finding{}, sigs: map[string]stats.Signal{}}
		scoreFrameworkDefaults(gotAcc, got)
		scoreFrameworkDefaults(wantAcc, want)
		if !reflect.DeepEqual(gotAcc.sigs, wantAcc.sigs) || !reflect.DeepEqual(gotAcc.f.Frames, wantAcc.f.Frames) {
			t.Fatalf("seed=%d case=%d score/signals/frames differ: %#v %#v", seed, ci, gotAcc, wantAcc)
		}
		for fw, state := range want.fw {
			for feat := range state.feats {
				if fw == "Cobalt Strike" {
					counts[feat]++
				}
			}
		}
	}
	for _, uri := range cobaltFrozen[0].Values {
		want := "GET default URI " + uri + " with bare base64 Cookie metadata"
		if counts[want] == 0 {
			t.Errorf("default URI branch not hit: %s", uri)
		}
	}
	for _, feature := range []string{"POST /submit.php?id=<n> (task output)", "stager URI " + paths[92] + " (checksum8 = 92)", "stager URI " + paths[93] + " (checksum8 = 93)", "empty text/plain 404"} {
		if counts[feature] == 0 {
			t.Errorf("positive branch not hit: %s", feature)
		}
	}
	t.Logf("seed=%d channels=%d messages=%d cobalt_branch_hits=%v checksum_examples=%s,%s", seed, len(cases), func() int {
		n := 0
		for _, c := range cases {
			n += len(c)
		}
		return n
	}(), counts, paths[92], paths[93])
}

var alphaNum = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

func TestCobaltSchemaDenials(t *testing.T) {
	original, err := os.ReadFile("../../data/framework-fingerprints.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, old, new string }{
		{"quoted status", "status: 404", "status: \"404\""},
		{"quoted elevated weight", "elevated_weight: 0.70", "elevated_weight: \"0.70\""},
		{"checksum duplicate", "checksums: [92, 93]", "checksums: [92, 92]"},
		{"checksum range", "checksums: [92, 93]", "checksums: [92, 256]"},
		{"unknown placeholder", "{path} with bare", "{path} {unknown} with bare"},
		{"new legacy field", "kind: uri_exact\n            message: request", "kind: uri_exact\n            path: /bad\n            message: request"},
		{"unknown field", "            status: 404", "            status: 404\n            expression: '.*'"},
		{"wrong path type", "            path: /submit.php", "            path: 17"},
		{"missing source", "        source:\n          id: v11a-cobaltstrike-http-legacy-code", "        source: null\n          id: v11a-cobaltstrike-http-legacy-code"},
		{"duplicate debt id", "debt_id: B33-D07-CS-HTTP-002", "debt_id: B33-D07-CS-HTTP-001"},
		{"YAML alias", "            method: GET", "            method: &m GET"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mut := strings.Replace(string(original), tc.old, tc.new, 1)
			if mut == string(original) {
				t.Fatal("mutation not applied")
			}
			if _, err := data.ParseProfiles([]byte(mut)); err == nil {
				t.Fatal("invalid schema accepted")
			}
		})
	}
	t.Run("verify true does not activate Cobalt", func(t *testing.T) {
		p, err := data.Load()
		if err != nil {
			t.Fatal(err)
		}
		p.Frameworks[3].FieldGroups["http"] = func() data.FieldGroup { g := p.Frameworks[3].FieldGroups["http"]; g.Verify = true; return g }()
		if _, err := registeredFrameworkHTTPItems(p); err == nil {
			t.Fatal("verify:true activated unapproved Cobalt profile")
		}
	})
	t.Run("non-Cobalt kind forbidden", func(t *testing.T) {
		p, err := data.Load()
		if err != nil {
			t.Fatal(err)
		}
		p.Frameworks[1].FieldGroups["http"].Items[0].Kind = "get_default_uri_b64_cookie"
		if _, err := registeredFrameworkHTTPItems(p); err == nil {
			t.Fatal("Cobalt kind accepted outside Cobalt")
		}
	})
}

func TestCobaltChecksumBranchExamples(t *testing.T) {
	for _, sum := range []int{92, 93} {
		p := ""
		for a := 0; a < 62 && p == ""; a++ {
			for b := 0; b < 62 && p == ""; b++ {
				for c := 0; c < 62 && p == ""; c++ {
					for d := 0; d < 62; d++ {
						candidate := fmt.Sprintf("/%c%c%c%c", alphaNum[a], alphaNum[b], alphaNum[c], alphaNum[d])
						got, ok := checksum8Sum(candidate)
						if ok && got == sum {
							p = candidate
							break
						}
					}
				}
			}
		}
		if p == "" {
			t.Fatalf("no path for sum %d", sum)
		}
		t.Logf("sum %d path %s", sum, p)
	}
}

func TestCobaltFrozenTableCoverageMeta(t *testing.T) {
	p, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	registered, err := registeredFrameworkHTTPItems(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"covenant/http", "merlin/http", "poshc2/http", "cobaltstrike/http"}
	if len(registered) != len(want) {
		t.Fatalf("registered groups %v", registered)
	}
	for _, key := range want {
		if _, ok := registered[key]; !ok {
			t.Errorf("missing registered group %s", key)
		}
	}
	// Execute each framework's own frozen-table comparison here; this is
	// runtime verification rather than a declared-test-name inventory.
	t.Run("Covenant frozen", func(t *testing.T) {
		items, err := covenantHTTPItems(p)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]frozenItem, 0, len(items))
		for _, it := range items {
			got = append(got, frozenItem{it.Kind, it.Message, it.Header, it.Value, it.Values, it.Feature, it.Weight})
		}
		if !reflect.DeepEqual(got, frozenCovenantHTTP) {
			t.Fatalf("Covenant frozen mismatch")
		}
	})
	t.Run("Merlin frozen", func(t *testing.T) {
		if got := merlinItemsFromProfiles(p); !reflect.DeepEqual(got, frozenMerlinHTTP) {
			t.Fatalf("Merlin frozen mismatch")
		}
	})
	t.Run("PoshC2 frozen", func(t *testing.T) {
		if got := poshItems(p); !reflect.DeepEqual(projectPosh(got), frozenPoshV11a) {
			t.Fatalf("PoshC2 frozen mismatch")
		}
	})
	t.Run("Cobalt frozen", func(t *testing.T) {
		got := registered["cobaltstrike/http"]
		if len(got) != len(cobaltFrozen) {
			t.Fatalf("Cobalt item count")
		}
		for i := range got {
			a, b := got[i], cobaltFrozen[i]
			a.Values = nil
			b.Values = nil
			if !reflect.DeepEqual(a, b) {
				t.Fatalf("Cobalt item %d mismatch", i)
			}
			if i == 0 && !sameStringSet(registered["cobaltstrike/http"][i].Values, cobaltFrozen[i].Values) {
				t.Fatal("Cobalt URI set mismatch")
			}
		}
	})
}
