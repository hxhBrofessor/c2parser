package engine

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"c2parser/data"
)

type poshFrozen struct {
	id, debt, loc, kind, msg, method, header, value, feature, reason string
	values                                                           []string
	weight                                                           float64
}

var frozenPoshV11a = []poshFrozen{
	{"poshc2-http-cookie-session-prefix", "B33-D07-POSH-HTTP-001", "repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:131-132", "cookie_prefix", "request", "", "cookie", "SessionID=", "Cookie SessionID=", "", nil, .3},
	{"poshc2-http-server-raw-apache-space", "B33-D07-POSH-HTTP-002", "repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:163-164", "response_server_raw_exact", "response", "", "", "Apache ", "\"Server: Apache \" with trailing space", "", nil, .6},
	{"poshc2-http-http10-content-type-case", "B33-D07-POSH-HTTP-003", "repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:166-167", "response_proto_and_raw_header_name", "response", "", "Content-type", "HTTP/1.0", "HTTP/1.0 response with lower-case Content-type", "", nil, .3},
	{"poshc2-http-iis-footer", "B33-D07-POSH-HTTP-004", "repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:169-170", "body_contains", "response", "", "", "IIS ASP.NET 2.0.43451 Server", "404 footer IIS ASP.NET 2.0.43451", "", nil, .7},
	{"poshc2-http-apache-debian-footer", "B33-D07-POSH-HTTP-005", "repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:172-173", "body_contains", "response", "", "", "<address>Apache (Debian) Server", "unversioned Apache (Debian) 404 footer", "", nil, .5},
	{"poshc2-http-slack-app-marker", "B33-D07-POSH-HTTP-006", "repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:175-176", "body_contains", "response", "", "", "slack-app-id\" content=\"#av33f33\"", "200 page slack-app-id #av33f33", "", nil, .8},
}

func projectPosh(items []data.Item) []poshFrozen {
	out := make([]poshFrozen, 0, len(items))
	for _, x := range items {
		out = append(out, poshFrozen{x.ID, x.DebtID, x.Locator, x.Kind, x.Message, x.Method, x.Header, x.Value, x.Feature, "", x.Values, x.Weight})
	}
	return out
}
func poshItems(p data.Profiles) []data.Item {
	for _, fw := range p.Frameworks {
		if fw.ID == "poshc2" {
			return fw.FieldGroups["http"].Items
		}
	}
	return nil
}
func TestPoshC2ProfileMatchesFrozenV11aTable(t *testing.T) {
	p, e := data.Load()
	if e != nil {
		t.Fatal(e)
	}
	got := poshItems(p)
	if !reflect.DeepEqual(projectPosh(got), frozenPoshV11a) {
		t.Fatalf("PoshC2 frozen v11a table mismatch: %#v", projectPosh(got))
	}
	if _, e = registeredFrameworkHTTPItems(p); e != nil {
		t.Fatal(e)
	}
}
func TestPoshC2FrozenTableRejectsBehaviorMutations(t *testing.T) {
	original, err := os.ReadFile("../../data/framework-fingerprints.yaml")
	if err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(original)
	cases := []struct{ name, old, replacement string }{
		{"cookie prefix", "value: SessionID=", "value: sessionID="},
		{"cookie feature", "feature: Cookie SessionID=", "feature: Cookie SessionID altered"},
		{"cookie weight", "weight: 0.3\n            reason: External fingerprint provenance pending; this item preserves only the pinned v11a predicate.", "weight: 0.31\n            reason: External fingerprint provenance pending; this item preserves only the pinned v11a predicate."},
		{"server trailing space", "value: \"Apache \"", "value: \"Apache\""},
		{"protocol", "value: HTTP/1.0", "value: HTTP/1.1"},
		{"raw header casing", "header: Content-type", "header: Content-Type"},
		{"body marker byte", "value: IIS ASP.NET 2.0.43451 Server", "value: IIS ASP.NET 2.0.43451 serveR"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := bytes.Replace(original, []byte(tc.old), []byte(tc.replacement), 1)
			if bytes.Equal(mutated, original) {
				t.Fatal("mutation target missing")
			}
			p := parsePoshMutationFile(t, mutated)
			if reflect.DeepEqual(projectPosh(poshItems(p)), frozenPoshV11a) {
				t.Fatal("frozen oracle accepted behavior mutation")
			}
			if _, err := registeredFrameworkHTTPItems(p); tc.name != "response order" && err != nil {
				t.Fatalf("metadata-only registry rejected valid predicate change: %v", err)
			}
			if sha256.Sum256(original) != wantHash {
				t.Fatalf("source YAML memory baseline changed case %d", i+1)
			}
			current, err := os.ReadFile("../../data/framework-fingerprints.yaml")
			if err != nil || sha256.Sum256(current) != wantHash {
				t.Fatalf("production YAML changed case %d", i+1)
			}
			t.Logf("mutation %d production YAML SHA-256 unchanged=%x", i+1, wantHash)
		})
	}
	t.Run("response order", func(t *testing.T) {
		mutated := swapMerlinItemBlocks(original, "poshc2-http-iis-footer", "poshc2-http-apache-debian-footer")
		if bytes.Equal(mutated, original) {
			t.Fatal("order mutation failed")
		}
		p := parsePoshMutationFile(t, mutated)
		if reflect.DeepEqual(projectPosh(poshItems(p)), frozenPoshV11a) {
			t.Fatal("frozen oracle accepted reordered items")
		}
		if _, err := registeredFrameworkHTTPItems(p); err == nil {
			t.Fatal("closed registry accepted reordered IDs")
		}
		if sha256.Sum256(original) != wantHash {
			t.Fatal("original source hash changed")
		}
		t.Logf("mutation response order production YAML SHA-256 unchanged=%x", wantHash)
	})
	reasonOnlyBytes := bytes.Replace(original, []byte("External fingerprint provenance pending; this item preserves only the pinned v11a predicate."), []byte("External fingerprint provenance pending; descriptive note."), 1)
	reasonOnly := parsePoshMutationFile(t, reasonOnlyBytes)
	if !reflect.DeepEqual(projectPosh(poshItems(reasonOnly)), frozenPoshV11a) {
		t.Fatal("reason-only change affected predicate oracle")
	}
	current, err := os.ReadFile("../../data/framework-fingerprints.yaml")
	if err != nil || sha256.Sum256(current) != wantHash {
		t.Fatal("production YAML source hash differs after mutation cases")
	}
	t.Logf("negative-control reason-only change production YAML SHA-256 unchanged=%x", wantHash)
}

func parsePoshMutationFile(t *testing.T, src []byte) data.Profiles {
	t.Helper()
	path := filepath.Join(t.TempDir(), "framework-fingerprints.yaml")
	if err := os.WriteFile(path, src, 0600); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := data.ParseProfiles(fixture)
	if err != nil {
		t.Fatalf("disposable mutation file must remain valid YAML/schema: %v", err)
	}
	return p
}

func TestPoshRegistryFailsClosed(t *testing.T) {
	base, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*data.Profiles)
	}{
		{"missing item", func(p *data.Profiles) {
			g := p.Frameworks[2].FieldGroups["http"]
			g.Items = g.Items[:5]
			p.Frameworks[2].FieldGroups["http"] = g
		}},
		{"extra item", func(p *data.Profiles) {
			g := p.Frameworks[2].FieldGroups["http"]
			g.Items = append(g.Items, g.Items[0])
			p.Frameworks[2].FieldGroups["http"] = g
		}},
		{"duplicate debt", func(p *data.Profiles) {
			g := p.Frameworks[2].FieldGroups["http"]
			g.Items[1].DebtID = g.Items[0].DebtID
			p.Frameworks[2].FieldGroups["http"] = g
		}},
		{"duplicate item ID", func(p *data.Profiles) {
			g := p.Frameworks[2].FieldGroups["http"]
			g.Items[1].ID = g.Items[0].ID
			p.Frameworks[2].FieldGroups["http"] = g
		}},
		{"wrong locator", func(p *data.Profiles) {
			g := p.Frameworks[2].FieldGroups["http"]
			g.Items[0].Locator = strings.Replace(g.Items[0].Locator, "131-132", "132-133", 1)
			p.Frameworks[2].FieldGroups["http"] = g
		}},
		{"unsupported kind", func(p *data.Profiles) {
			g := p.Frameworks[2].FieldGroups["http"]
			g.Items[0].Kind = "header_exact"
			p.Frameworks[2].FieldGroups["http"] = g
		}},
		{"wrong direction", func(p *data.Profiles) {
			g := p.Frameworks[2].FieldGroups["http"]
			g.Items[0].Message = "response"
			p.Frameworks[2].FieldGroups["http"] = g
		}},
		{"verify true", func(p *data.Profiles) {
			g := p.Frameworks[2].FieldGroups["http"]
			g.Verify = true
			p.Frameworks[2].FieldGroups["http"] = g
		}},
		{"new group", func(p *data.Profiles) {
			fw := p.Frameworks[2]
			fw.FieldGroups["dns"] = data.FieldGroup{Evidence: data.EvidenceUnknown, Verify: true, Reason: "test", Items: []data.Item{}}
			p.Frameworks[2] = fw
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := cloneProfiles(base)
			tc.mutate(&cp)
			if _, err := registeredFrameworkHTTPItems(cp); err == nil {
				t.Fatal("registry accepted unregistered structure")
			}
		})
	}
}
func TestPoshC2BoundaryPredicates(t *testing.T) {
	p, e := data.Load()
	if e != nil {
		t.Fatal(e)
	}
	profiles, e := registeredFrameworkHTTPItems(p)
	if e != nil {
		t.Fatal(e)
	}
	eng := &Engine{covenantHTTP: profiles["covenant/http"], merlinHTTP: profiles["merlin/http"], poshHTTP: profiles["poshc2/http"]}
	cases := []struct {
		name string
		m    *httpMsg
		want int
	}{
		{"cookie exact", &httpMsg{req: true, hdr: map[string]string{"cookie": "SessionID=x"}}, 1},
		{"cookie lower", &httpMsg{req: true, hdr: map[string]string{"cookie": "sessionid=x"}}, 0},
		{"cookie prefixed", &httpMsg{req: true, hdr: map[string]string{"cookie": "xSessionID=x"}}, 0},
		{"cookie leading space", &httpMsg{req: true, hdr: map[string]string{"cookie": " SessionID=x"}}, 0},
		{"raw server exact", &httpMsg{hdr: map[string]string{}, serverRaw: "Apache "}, 1},
		{"raw server no space", &httpMsg{hdr: map[string]string{}, serverRaw: "Apache"}, 0},
		{"raw server double space", &httpMsg{hdr: map[string]string{}, serverRaw: "Apache  "}, 0},
		{"header raw exact", &httpMsg{hdr: map[string]string{}, proto: "HTTP/1.0", order: []string{"Content-type"}}, 1},
		{"header canonical case", &httpMsg{hdr: map[string]string{}, proto: "HTTP/1.0", order: []string{"Content-Type"}}, 0},
		{"header lower case", &httpMsg{hdr: map[string]string{}, proto: "HTTP/1.0", order: []string{"content-type"}}, 0},
		{"wrong protocol", &httpMsg{hdr: map[string]string{}, proto: "HTTP/1.1", order: []string{"Content-type"}}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := &httpChannel{}
			eng.matchFrameworkDefaults(ch, tc.m)
			got := 0
			if st := ch.fw["PoshC2"]; st != nil {
				got = len(st.feats)
			}
			if got != tc.want {
				t.Fatalf("features=%d want %d", got, tc.want)
			}
		})
	}
}
func TestPoshC2WholeFunctionDifferential30000(t *testing.T) {
	const seed int64 = 0x504F53484332
	rng := rand.New(rand.NewSource(seed))
	e := &Engine{}
	counts := make([]int, 6)
	values := []string{"SessionID=x", "sessionid=x", "xSessionID=x", " SessionID=x", "Apache ", "Apache", "Apache  ", "HTTP/1.0", "HTTP/1.1", "IIS ASP.NET 2.0.43451 Server", "<address>Apache (Debian) Server", "slack-app-id\" content=\"#av33f33\"", "noise", "application/octet-stream"}
	for n := 0; n < 30000; n++ {
		a, b := &httpChannel{}, &httpChannel{}
		frames := 1 + rng.Intn(4)
		for j := 0; j < frames; j++ {
			req := rng.Intn(2) == 0
			cookie := values[rng.Intn(len(values))]
			body := []byte(values[rng.Intn(len(values))])
			proto := values[rng.Intn(len(values))]
			hdrName := []string{"Content-type", "Content-Type", "content-type", "user-agent", "server"}[rng.Intn(5)]
			m := &httpMsg{req: req, method: []string{"GET", "POST", "post", "PUT"}[rng.Intn(4)], uri: []string{"/", "/en-us/index.html", "/submit.php?id=1", "/ca"}[rng.Intn(4)], proto: proto, status: []int{200, 404}[rng.Intn(2)], hdr: map[string]string{"cookie": cookie, "user-agent": covenantUA, "content-type": "text/plain", "server": "Microsoft-IIS/7.5", "authorization": "Bearer eyJfixture", "content-length": "0"}, order: []string{hdrName}, serverRaw: values[rng.Intn(len(values))], head: body, bodyLen: int64(rng.Intn(80)), frame: int64(n*4 + j)}
			e.matchFrameworkDefaults(a, m)
			matchFrameworkDefaultsV11aReference(&Engine{}, b, m)
			if !reflect.DeepEqual(a.fw, b.fw) {
				t.Fatalf("seed=%d case=%d current=%#v legacy=%#v", seed, n, a.fw, b.fw)
			}
		}
		if st := a.fw["PoshC2"]; st != nil {
			for i, x := range frozenPoshV11a {
				if _, ok := st.feats[x.feature]; ok {
					counts[i]++
				}
			}
		}
	}
	for i, n := range counts {
		if n == 0 {
			t.Fatalf("seed %d never hit predicate %d", seed, i)
		}
	}
	t.Logf("seed=%d cases=30000 mismatches=0 posh_hits_by_predicate=%v", seed, counts)
}

// Independent literal copy of the full v11a function follows from commit 425897e8c36005e001e6f6254ede16117194f9d2, internal/engine/httpdefaults.go:97-182. The complete pre-edit source hash is recorded in the Round-0 private manifest.
func matchFrameworkDefaultsV11aReference(e *Engine, ch *httpChannel, m *httpMsg) {
	f := m.frame
	if m.req {
		path, query, _ := strings.Cut(m.uri, "?")
		ua, ck := m.hdr["user-agent"], m.hdr["cookie"]
		ct := strings.TrimSpace(m.hdr["content-type"])

		// Covenant
		if covenantURIs[path] {
			ch.fwAdd("Covenant", "URI "+path, 0.25, f)
		}
		if ua == covenantUA {
			ch.fwAdd("Covenant", "Chrome/41.0.2228.0 User-Agent", 0.45, f)
		}
		if strings.Contains(ck, "SESSIONID=1552332971750") {
			ch.fwAdd("Covenant", "Cookie SESSIONID=1552332971750", 0.9, f)
		}
		if bytes.HasPrefix(m.head, []byte("i=a19ea23062db990386a3a478cb89d52e&data=")) {
			ch.fwAdd("Covenant", "POST body template i=a19ea23062db…&data=", 0.9, f)
		}

		// Merlin
		if m.method == "POST" && path == "/" {
			ch.fwAdd("Merlin", "POST /", 0.1, f)
		}
		if strings.EqualFold(ct, "application/octet-stream; charset=utf-8") {
			ch.fwAdd("Merlin", "Content-Type application/octet-stream; charset=utf-8", 0.5, f)
		}
		if strings.HasPrefix(m.hdr["authorization"], "Bearer eyJ") {
			ch.fwAdd("Merlin", "Authorization: Bearer <JWT>", 0.3, f)
		}
		if ua == merlinUA {
			ch.fwAdd("Merlin", "Chrome/40.0.2214.85 User-Agent", 0.55, f)
		}

		// PoshC2
		if strings.HasPrefix(ck, "SessionID=") {
			ch.fwAdd("PoshC2", "Cookie SessionID=", 0.3, f)
		}

		// Cobalt Strike (no malleable profile)
		if m.method == "GET" && csDefaultURIs[path] && b64CookieRe.MatchString(ck) {
			ch.fwAdd("Cobalt Strike", "GET default URI "+path+" with bare base64 Cookie metadata", 0.6, f)
		}
		if m.method == "POST" && path == "/submit.php" && csSubmitQRe.MatchString(query) {
			s := 0.55
			if strings.EqualFold(ct, "application/octet-stream") {
				s = 0.7
			}
			ch.fwAdd("Cobalt Strike", "POST /submit.php?id=<n> (task output)", s, f)
		}
		if m.method == "GET" {
			if sum, ok := checksum8(path); ok {
				ch.fwAdd("Cobalt Strike", fmt.Sprintf("stager URI %s (checksum8 = %d)", path, sum), 0.35, f)
			}
		}
		return
	}

	sv, ct := m.hdr["server"], strings.TrimSpace(m.hdr["content-type"])
	// Covenant
	if sv == "Microsoft-IIS/7.5" {
		ch.fwAdd("Covenant", "Server: Microsoft-IIS/7.5", 0.15, f)
	}
	if bytes.Contains(m.head, []byte("// Hello World! ")) || bytes.Contains(m.head, []byte("<title>Hello World!</title>")) {
		ch.fwAdd("Covenant", "Hello World! response template", 0.4, f)
	}
	// PoshC2 (CPython http.server underneath)
	if m.serverRaw == "Apache " {
		ch.fwAdd("PoshC2", `"Server: Apache " with trailing space`, 0.6, f)
	}
	if m.proto == "HTTP/1.0" && hasHeaderName(m, "Content-type") {
		ch.fwAdd("PoshC2", "HTTP/1.0 response with lower-case Content-type", 0.3, f)
	}
	if bytes.Contains(m.head, []byte("IIS ASP.NET 2.0.43451 Server")) {
		ch.fwAdd("PoshC2", "404 footer IIS ASP.NET 2.0.43451", 0.7, f)
	}
	if bytes.Contains(m.head, []byte("<address>Apache (Debian) Server")) {
		ch.fwAdd("PoshC2", "unversioned Apache (Debian) 404 footer", 0.5, f)
	}
	if bytes.Contains(m.head, []byte(`slack-app-id" content="#av33f33"`)) {
		ch.fwAdd("PoshC2", "200 page slack-app-id #av33f33", 0.8, f)
	}
	// Cobalt Strike
	if m.status == 404 && ct == "text/plain" && m.bodyLen == 0 && m.hdr["content-length"] == "0" {
		ch.fwAdd("Cobalt Strike", "empty text/plain 404", 0.2, f)
	}
}
