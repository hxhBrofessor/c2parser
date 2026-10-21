package engine

import (
	"bytes"
	"crypto/sha256"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"c2parser/data"
	"c2parser/internal/stats"
)

// frozenMerlinHTTP is transcribed from the pinned v11a implementation at
// httpdefaults.go:117-127. It is deliberately independent of the YAML asset.
var frozenMerlinHTTP = []data.Item{
	{ID: "merlin-http-post-root", DebtID: "B33-D07-MER-HTTP-001", Locator: "repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:117-118", Kind: "request_method_uri_exact", Message: "request", Method: "POST", Value: "/", Feature: "POST /", Weight: 0.1, Reason: "External provenance pending; this item preserves only the pinned v11a predicate."},
	{ID: "merlin-http-content-type", DebtID: "B33-D07-MER-HTTP-002", Locator: "repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:120-121", Kind: "header_trim_equal_fold", Message: "request", Header: "content-type", Value: "application/octet-stream; charset=utf-8", Feature: "Content-Type application/octet-stream; charset=utf-8", Weight: 0.5, Reason: "External provenance pending; this item preserves only the pinned v11a predicate."},
	{ID: "merlin-http-authorization-prefix", DebtID: "B33-D07-MER-HTTP-003", Locator: "repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:123-124", Kind: "header_prefix", Message: "request", Header: "authorization", Value: "Bearer eyJ", Feature: "Authorization: Bearer <JWT>", Weight: 0.3, Reason: "External provenance pending; this item preserves only the pinned v11a predicate."},
	{ID: "merlin-http-user-agent", DebtID: "B33-D07-MER-HTTP-004", Locator: "repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:126-127", Kind: "header_exact", Message: "request", Header: "user-agent", Value: "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36", Feature: "Chrome/40.0.2214.85 User-Agent", Weight: 0.55, Reason: "External provenance pending; this item preserves only the pinned v11a predicate."},
}

func merlinItemsFromProfiles(p data.Profiles) []data.Item {
	for _, fw := range p.Frameworks {
		if fw.ID == "merlin" {
			return fw.FieldGroups["http"].Items
		}
	}
	return nil
}

func TestMerlinProfileMatchesFrozenV11aTable(t *testing.T) {
	p, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := merlinItemsFromProfiles(p); !reflect.DeepEqual(got, frozenMerlinHTTP) {
		t.Fatalf("Merlin HTTP profile differs from frozen v11a predicate table\n got: %#v\nwant: %#v", got, frozenMerlinHTTP)
	}
	if _, err := registeredFrameworkHTTPItems(p); err != nil {
		t.Fatalf("production profile registry rejected frozen profile: %v", err)
	}
}

func TestMerlinRegistryFailsClosed(t *testing.T) {
	p, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*data.Profiles)
	}{
		{"missing merlin item", func(p *data.Profiles) {
			p.Frameworks[1].FieldGroups["http"] = removeFirst(p.Frameworks[1].FieldGroups["http"])
		}},
		{"extra covenant item", func(p *data.Profiles) {
			g := p.Frameworks[0].FieldGroups["http"]
			g.Items = append(g.Items, g.Items[0])
			p.Frameworks[0].FieldGroups["http"] = g
		}},
		{"wrong locator", func(p *data.Profiles) {
			g := p.Frameworks[1].FieldGroups["http"]
			g.Items[0].Locator = strings.Replace(g.Items[0].Locator, "117-118", "118-119", 1)
			p.Frameworks[1].FieldGroups["http"] = g
		}},
		{"wrong item debt", func(p *data.Profiles) {
			g := p.Frameworks[1].FieldGroups["http"]
			g.Items[0].DebtID = "unregistered"
			p.Frameworks[1].FieldGroups["http"] = g
		}},
		{"missing item debt reason", func(p *data.Profiles) {
			g := p.Frameworks[1].FieldGroups["http"]
			g.Items[0].Reason = ""
			p.Frameworks[1].FieldGroups["http"] = g
		}},
		{"wrong source citation", func(p *data.Profiles) {
			s := *p.Frameworks[1].FieldGroups["http"].Source
			s.Citation = "external confirmation"
			g := p.Frameworks[1].FieldGroups["http"]
			g.Source = &s
			p.Frameworks[1].FieldGroups["http"] = g
		}},
		{"wrong matcher kind", func(p *data.Profiles) {
			g := p.Frameworks[1].FieldGroups["http"]
			g.Items[0].Kind = "uri_exact"
			g.Items[0].Method = ""
			p.Frameworks[1].FieldGroups["http"] = g
		}},
		{"wrong weight", func(p *data.Profiles) {
			g := p.Frameworks[1].FieldGroups["http"]
			g.Items[1].Weight = 0.6
			p.Frameworks[1].FieldGroups["http"] = g
		}},
		{"extra field group", func(p *data.Profiles) {
			p.Frameworks[1].FieldGroups["dns"] = data.FieldGroup{Evidence: data.EvidenceUnknown, Verify: true, Reason: "test-only empty group", Items: []data.Item{}}
		}},
		{"wrong message direction", func(p *data.Profiles) {
			g := p.Frameworks[1].FieldGroups["http"]
			g.Items[3].Message = "response"
			p.Frameworks[1].FieldGroups["http"] = g
		}},
		{"unregistered framework", func(p *data.Profiles) { p.Frameworks[1].ID = "other" }},
		{"verify true is not consumable", func(p *data.Profiles) {
			g := p.Frameworks[1].FieldGroups["http"]
			g.Verify = true
			p.Frameworks[1].FieldGroups["http"] = g
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := cloneProfiles(p)
			tc.mutate(&cp)
			if _, err := registeredFrameworkHTTPItems(cp); err == nil {
				t.Fatal("unregistered profile accepted")
			}
		})
	}
}

func removeFirst(g data.FieldGroup) data.FieldGroup {
	g.Items = append([]data.Item(nil), g.Items[1:]...)
	return g
}
func cloneProfiles(p data.Profiles) data.Profiles {
	out := data.Profiles{SchemaVersion: p.SchemaVersion, Frameworks: append([]data.Framework(nil), p.Frameworks...)}
	for i := range out.Frameworks {
		fw := out.Frameworks[i]
		groups := map[string]data.FieldGroup{}
		for k, g := range fw.FieldGroups {
			g.Items = append([]data.Item(nil), g.Items...)
			if g.Source != nil {
				s := *g.Source
				g.Source = &s
			}
			groups[k] = g
		}
		fw.FieldGroups = groups
		out.Frameworks[i] = fw
	}
	return out
}

// Each mutation is applied to a disposable YAML file. The production YAML is
// never mutated and its SHA-256 is checked after every case.
func TestMerlinFrozenTableRejectsBehavioralMutations(t *testing.T) {
	original, err := os.ReadFile("../../data/framework-fingerprints.yaml")
	if err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(original)
	tests := []struct{ name, old, replacement string }{
		{"uri path", "            value: /\n            feature: POST /", "            value: /home\n            feature: POST /"},
		{"content-type value", "            value: application/octet-stream; charset=utf-8", "            value: application/octet-stream; charset=utf-8; x=1"},
		{"authorization prefix", "            value: Bearer eyJ", "            value: Bearer eyK"},
		{"user-agent value", "Chrome/40.0.2214.85 Safari/537.36", "Chrome/40.0.2214.86 Safari/537.36"},
		{"weight", "            weight: 0.5", "            weight: 0.6"},
		{"case-sensitive method", "            method: POST", "            method: post"},
		{"order", "", ""},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mutated := bytes.Replace(original, []byte(tc.old), []byte(tc.replacement), 1)
			if tc.name == "order" {
				mutated = swapMerlinItemBlocks(original, "merlin-http-authorization-prefix", "merlin-http-user-agent")
			}
			if bytes.Equal(mutated, original) {
				t.Fatal("mutation target not found")
			}
			path := filepath.Join(t.TempDir(), "framework-fingerprints.yaml")
			if err := os.WriteFile(path, mutated, 0600); err != nil {
				t.Fatal(err)
			}
			fixture, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			p, err := data.ParseProfiles(fixture)
			if err != nil {
				t.Fatalf("mutation was not syntactically/schema valid: %v", err)
			}
			got := merlinItemsFromProfiles(p)
			if reflect.DeepEqual(got, frozenMerlinHTTP) {
				t.Fatal("frozen table accepted changed behavior")
			}
			if after := sha256.Sum256(original); after != wantHash {
				t.Fatalf("original YAML bytes changed after mutation %d", i+1)
			}
			current, err := os.ReadFile("../../data/framework-fingerprints.yaml")
			if err != nil || sha256.Sum256(current) != wantHash {
				t.Fatalf("working YAML changed after mutation %d", i+1)
			} else {
				t.Logf("restored production YAML SHA-256=%x", sha256.Sum256(current))
			}
		})
	}
}

func TestMerlinFrozenTableRejectsDirectionMutation(t *testing.T) {
	p, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	items := merlinItemsFromProfiles(p)
	items[3].Message = "response"
	if reflect.DeepEqual(items, frozenMerlinHTTP) {
		t.Fatal("frozen table accepted wrong direction")
	}
}

func swapMerlinItemBlocks(src []byte, first, second string) []byte {
	lines := strings.SplitAfter(string(src), "\n")
	starts := map[string]int{}
	for i, line := range lines {
		for _, id := range []string{first, second} {
			if strings.Contains(line, "- id: "+id) {
				starts[id] = i
			}
		}
	}
	a, aok := starts[first]
	b, bok := starts[second]
	if !aok || !bok || a >= b {
		return src
	}
	end := func(start int) int {
		for i := start + 1; i < len(lines); i++ {
			if strings.HasPrefix(lines[i], "          - id:") {
				return i
			}
		}
		return len(lines)
	}
	aEnd, bEnd := end(a), end(b)
	if aEnd != b {
		return src
	}
	out := append([]string{}, lines[:a]...)
	out = append(out, lines[b:bEnd]...)
	out = append(out, lines[a:aEnd]...)
	out = append(out, lines[bEnd:]...)
	return []byte(strings.Join(out, ""))
}

func TestMerlinDifferentialV11aMatcherDeterministic20K(t *testing.T) {
	const seed int64 = 0x4d45524c494e
	const count = 20000
	rng := rand.New(rand.NewSource(seed))
	e := New(Config{})
	coverage := map[string]int{}
	positiveCases := 0
	for i := 0; i < count; i++ {
		want, got := &httpChannel{}, &httpChannel{}
		events := make([]*httpMsg, 0, 6)
		n := 1 + rng.Intn(6)
		for j := 0; j < n; j++ {
			events = append(events, deterministicMerlinMessage(i*7+j, rng))
		}
		if i%5 == 0 {
			events = append(events, deterministicMerlinMessage(i*7, rng))
		}
		for j, m := range events {
			m.frame = int64(i*10 + j + 1)
			if m.hdr == nil {
				m.hdr = map[string]string{}
			}
			legacyV11aMerlin(want, m)
			e.matchMerlinHTTP(got, m, m.frame)
		}
		if ws := want.fw["Merlin"]; ws != nil {
			positiveCases++
			for feature := range ws.feats {
				coverage[feature]++
			}
		}
		if !reflect.DeepEqual(want.fw, got.fw) {
			t.Fatalf("seed=%d case=%d mismatch: old=%#v new=%#v", seed, i, want.fw, got.fw)
		}
		oldAcc, newAcc := &acc{f: &Finding{}, sigs: map[string]stats.Signal{}}, &acc{f: &Finding{}, sigs: map[string]stats.Signal{}}
		scoreFrameworkDefaults(oldAcc, want)
		scoreFrameworkDefaults(newAcc, got)
		if !reflect.DeepEqual(oldAcc.sigs, newAcc.sigs) || !reflect.DeepEqual(oldAcc.f.Frames, newAcc.f.Frames) {
			t.Fatalf("seed=%d case=%d final score/frame mismatch: old=(%#v,%v) new=(%#v,%v)", seed, i, oldAcc.sigs, oldAcc.f.Frames, newAcc.sigs, newAcc.f.Frames)
		}
	}
	for _, item := range frozenMerlinHTTP {
		if coverage[item.Feature] == 0 {
			t.Fatalf("frozen predicate %q never triggered", item.ID)
		}
	}
	if positiveCases == 0 {
		t.Fatal("no positive differential case triggered")
	}
	t.Logf("cases=%d seed=%d positives=%d predicate_coverage=%v mismatches=0", count, seed, positiveCases, coverage)
	if count != 20000 {
		t.Fatalf("test count drift: %d", count)
	}
}

func deterministicMerlinMessage(i int, rng *rand.Rand) *httpMsg {
	msg := &httpMsg{req: true, hdr: map[string]string{}, frame: int64(i + 1)}
	switch i % 12 {
	case 0:
		msg.method, msg.uri = "POST", "/?q=1"
	case 1:
		msg.method, msg.uri = "post", "/"
	case 2:
		msg.hdr["content-type"] = "application/octet-stream; charset=utf-8"
	case 3:
		msg.hdr["content-type"] = " \tAPPLICATION/OCTET-STREAM; CHARSET=UTF-8\t "
	case 4:
		msg.hdr["content-type"] = "application/octet-stream; charset=utf-8x"
	case 5:
		msg.hdr["authorization"] = "Bearer eyJpayload"
	case 6:
		msg.hdr["authorization"] = "bearer eyJpayload"
	case 7:
		msg.hdr["user-agent"] = frozenMerlinHTTP[3].Value
	case 8:
		msg.hdr["user-agent"] = strings.ToLower(frozenMerlinHTTP[3].Value)
	case 9:
		msg.req = false
		msg.hdr["content-type"] = "application/octet-stream; charset=utf-8"
		msg.hdr["authorization"] = "Bearer eyJpayload"
		msg.hdr["user-agent"] = frozenMerlinHTTP[3].Value
	case 10:
		msg.method, msg.uri = "POST", "/"
		msg.hdr["content-type"] = "application/octet-stream; charset=utf-8"
		msg.hdr["authorization"] = "Bearer eyJpayload"
		msg.hdr["user-agent"] = frozenMerlinHTTP[3].Value
	case 11:
		methods := []string{"GET", "POST", "post", "PUT"}
		paths := []string{"/", "/?x=1", "/x", "/HOME"}
		msg.req = rng.Intn(5) != 0
		msg.method = methods[rng.Intn(len(methods))]
		msg.uri = paths[rng.Intn(len(paths))]
		if rng.Intn(4) == 0 {
			msg.hdr["content-type"] = randomHTTPValue(rng)
		}
	}
	return msg
}

func legacyV11aMerlin(ch *httpChannel, m *httpMsg) {
	if !m.req {
		return
	}
	path, _, _ := strings.Cut(m.uri, "?")
	ct := strings.TrimSpace(m.hdr["content-type"])
	f := m.frame
	if m.method == "POST" && path == "/" {
		ch.fwAdd("Merlin", "POST /", 0.1, f)
	}
	if strings.EqualFold(ct, "application/octet-stream; charset=utf-8") {
		ch.fwAdd("Merlin", "Content-Type application/octet-stream; charset=utf-8", 0.5, f)
	}
	if strings.HasPrefix(m.hdr["authorization"], "Bearer eyJ") {
		ch.fwAdd("Merlin", "Authorization: Bearer <JWT>", 0.3, f)
	}
	if m.hdr["user-agent"] == frozenMerlinHTTP[3].Value {
		ch.fwAdd("Merlin", "Chrome/40.0.2214.85 User-Agent", 0.55, f)
	}
}
func randomHTTPValue(r *rand.Rand) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 /;=-_"
	b := make([]byte, r.Intn(90))
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

func TestMerlinCovenantNonRegressionIsolated(t *testing.T) {
	e := New(Config{})
	ch := &httpChannel{}
	m := &httpMsg{req: true, method: "GET", uri: "/en-us/index.html", hdr: map[string]string{"user-agent": covenantUA}, frame: 41}
	e.matchFrameworkDefaults(ch, m)
	if ch.fw["Covenant"] == nil || ch.fw["Merlin"] != nil {
		t.Fatalf("Covenant-only input changed: %#v", ch.fw)
	}
}
