package engine

import (
	"bytes"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"c2parser/data"
	"c2parser/internal/stats"
)

// Framework default HTTP profiles. Covenant, Merlin and PoshC2 hard-code
// their HTTP literals in source; Cobalt Strike has well-documented no-profile
// defaults. Individual fields (a URI, a stale UA, "Server: Microsoft-IIS/7.5")
// are common on their own, so features are accumulated per HTTP channel and
// combined noisy-OR; a finding needs the combination to reach fwThreshold.
// Only near-unique literals (Covenant's SESSIONID constant and POST template,
// PoshC2's 404 footer) can reach it alone.
//
// Sources: cobbr/Covenant DefaultHttpProfile.yaml; Ne0nd0g/merlin-agent
// main.go and clients/http/http.go; nettitude/PoshC2 C2Server.py and
// resources/responses; Unit 42 "Cobalt Strike malleable C2 profile";
// SANS ISC 27204 (checksum8).

const (
	covenantUA  = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"
	merlinUA    = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36"
	fwThreshold = 0.65
)

// covenantURIs remains as immutable test-oracle inventory; runtime Covenant
// matching consumes the validated embedded profile below.
var covenantURIs = map[string]bool{"/en-us/index.html": true, "/en-us/docs.html": true, "/en-us/test.html": true}

type fwState struct {
	feats  map[string]float64
	frames []int64
}

var csDefaultURIs = map[string]bool{}

func init() {
	for _, u := range strings.Fields(`/ca /dpixel /__utm.gif /pixel.gif /g.pixel /dot.gif /updates.rss /fwlink /cm /cx
		/pixel /match /visit.js /load /push /ptj /j.ad /ga.js /en_US/all.js /activity /IE9CompatViewList.xml`) {
		csDefaultURIs[u] = true
	}
}

var (
	b64CookieRe   = regexp.MustCompile(`^[A-Za-z0-9+/]{40,}={0,2}$`)
	csSubmitQRe   = regexp.MustCompile(`^id=\d+$`)
	csStagerURIRe = regexp.MustCompile(`^/[A-Za-z0-9]{4}$`)
)

// checksum8 is Cobalt Strike / Metasploit's stager URI check: the byte sum
// of the 4-character path mod 256 is 92 (x86) or 93 (x64).
func checksum8(path string) (int, bool) {
	if !csStagerURIRe.MatchString(path) {
		return 0, false
	}
	sum := 0
	for i := 1; i < len(path); i++ {
		sum += int(path[i])
	}
	sum %= 256
	return sum, sum == 92 || sum == 93
}

func hasHeaderName(m *httpMsg, exact string) bool {
	for _, k := range m.order {
		if k == exact {
			return true
		}
	}
	return false
}

func (ch *httpChannel) fwAdd(fw, feat string, s float64, frame int64) {
	if ch.fw == nil {
		ch.fw = map[string]*fwState{}
	}
	st := ch.fw[fw]
	if st == nil {
		st = &fwState{feats: map[string]float64{}}
		ch.fw[fw] = st
	}
	if s > st.feats[feat] {
		st.feats[feat] = s
	}
	if len(st.frames) < 8 {
		st.frames = append(st.frames, frame)
	}
}

func loadFrameworkHTTPProfiles() (map[string][]data.Item, error) {
	p, err := data.Load()
	if err != nil {
		return nil, err
	}
	return registeredFrameworkHTTPItems(p)
}

func covenantHTTPItems(p data.Profiles) ([]data.Item, error) {
	profiles, err := registeredFrameworkHTTPItems(p)
	if err != nil {
		return nil, err
	}
	return append([]data.Item(nil), profiles["covenant/http"]...), nil
}

// registeredFrameworkHTTPItems admits only the two reviewed groups and their
// exact D-07 source/debt bindings. It is intentionally not a generic registry.
func registeredFrameworkHTTPItems(p data.Profiles) (map[string][]data.Item, error) {
	if p.SchemaVersion != 1 || len(p.Frameworks) != 2 {
		return nil, fmt.Errorf("UNAUTHORIZED_PROFILE_GROUP: expected exactly Covenant/http and Merlin/http")
	}
	if p.Frameworks[0].ID != "covenant" || p.Frameworks[1].ID != "merlin" {
		return nil, fmt.Errorf("UNAUTHORIZED_PROFILE_GROUP: framework iteration order differs from registry")
	}
	expected := map[string]struct {
		ids, locators        []string
		sourceID, debtPrefix string
		citation, reason     string
	}{
		"covenant": {ids: []string{"covenant-http-uri-index", "covenant-http-uri-docs", "covenant-http-uri-test", "covenant-http-user-agent", "covenant-http-cookie", "covenant-http-post-template", "covenant-http-server", "covenant-http-response-template"}, sourceID: "v11a-covenant-http-legacy-code", debtPrefix: "B33-D07-COV-HTTP-", citation: "Existing Covenant HTTP predicates in the pinned v11a implementation; this is code provenance, not external corroboration.", reason: "External provenance pending; this item-level register preserves only existing v11a behavior.", locators: []string{"103-104", "103-104", "103-104", "106-107", "109-110", "112-113", "156-157", "159-160"}},
		"merlin":   {ids: []string{"merlin-http-post-root", "merlin-http-content-type", "merlin-http-authorization-prefix", "merlin-http-user-agent"}, sourceID: "v11a-merlin-http-legacy-code", debtPrefix: "B33-D07-MER-HTTP-", citation: "Existing Merlin HTTP predicates in the pinned v11a implementation; code provenance only, external provenance pending.", reason: "External provenance pending; item-level records preserve only existing v11a behavior.", locators: []string{"117-118", "120-121", "123-124", "126-127"}},
	}
	profiles := make(map[string][]data.Item, 2)
	seenFramework, seenItems, seenDebts := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, fw := range p.Frameworks {
		want, ok := expected[fw.ID]
		if !ok || seenFramework[fw.ID] {
			return nil, fmt.Errorf("UNAUTHORIZED_PROFILE_GROUP: framework %q is not uniquely registered", fw.ID)
		}
		seenFramework[fw.ID] = true
		if len(fw.Aliases) != 0 || len(fw.FieldGroups) != 1 {
			return nil, fmt.Errorf("UNAUTHORIZED_PROFILE_GROUP: %s has unregistered field groups", fw.ID)
		}
		g, ok := fw.FieldGroups["http"]
		if !ok || g.Evidence != data.EvidenceUnknown || g.Verify || g.Source == nil || len(g.Items) != len(want.ids) {
			return nil, fmt.Errorf("PROFILE_ITEM_SET_MISMATCH: %s/http has unexpected status or item count", fw.ID)
		}
		if g.Source.ID != want.sourceID || g.Source.Citation != want.citation || g.Source.Revision != "425897e8c36005e001e6f6254ede16117194f9d2" || g.Source.Locator != "repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:matchFrameworkDefaults" || g.Reason != want.reason {
			return nil, fmt.Errorf("PROFILE_SOURCE_MISMATCH: %s/http is not the registered D-07 carry-forward", fw.ID)
		}
		for i, item := range g.Items {
			if item.ID != want.ids[i] || item.DebtID != fmt.Sprintf("%s%03d", want.debtPrefix, i+1) || item.Locator != "repo@425897e8c36005e001e6f6254ede16117194f9d2:internal/engine/httpdefaults.go:"+want.locators[i] {
				return nil, fmt.Errorf("PROFILE_ITEM_SET_MISMATCH: %s/http item %d has unexpected ID, debt or source locator", fw.ID, i)
			}
			if seenItems[item.ID] || seenDebts[item.DebtID] {
				return nil, fmt.Errorf("PROFILE_ITEM_SET_MISMATCH: duplicate item or debt ID")
			}
			seenItems[item.ID], seenDebts[item.DebtID] = true, true
			if fw.ID == "merlin" && !reflect.DeepEqual(item, expectedMerlinHTTPItems()[i]) {
				return nil, fmt.Errorf("PROFILE_ITEM_SET_MISMATCH: Merlin item %d differs from its registered exact predicate", i)
			}
		}
		profiles[fw.ID+"/http"] = append([]data.Item(nil), g.Items...)
	}
	if !seenFramework["covenant"] || !seenFramework["merlin"] {
		return nil, fmt.Errorf("PROFILE_ITEM_SET_MISMATCH: required framework is missing")
	}
	return profiles, nil
}

func expectedMerlinHTTPItems() []data.Item {
	const rev = "425897e8c36005e001e6f6254ede16117194f9d2"
	base := "repo@" + rev + ":internal/engine/httpdefaults.go:"
	return []data.Item{
		{ID: "merlin-http-post-root", DebtID: "B33-D07-MER-HTTP-001", Locator: base + "117-118", Kind: "request_method_uri_exact", Message: "request", Method: "POST", Value: "/", Feature: "POST /", Weight: 0.1, Reason: "External provenance pending; this item preserves only the pinned v11a predicate."},
		{ID: "merlin-http-content-type", DebtID: "B33-D07-MER-HTTP-002", Locator: base + "120-121", Kind: "header_trim_equal_fold", Message: "request", Header: "content-type", Value: "application/octet-stream; charset=utf-8", Feature: "Content-Type application/octet-stream; charset=utf-8", Weight: 0.5, Reason: "External provenance pending; this item preserves only the pinned v11a predicate."},
		{ID: "merlin-http-authorization-prefix", DebtID: "B33-D07-MER-HTTP-003", Locator: base + "123-124", Kind: "header_prefix", Message: "request", Header: "authorization", Value: "Bearer eyJ", Feature: "Authorization: Bearer <JWT>", Weight: 0.3, Reason: "External provenance pending; this item preserves only the pinned v11a predicate."},
		{ID: "merlin-http-user-agent", DebtID: "B33-D07-MER-HTTP-004", Locator: base + "126-127", Kind: "header_exact", Message: "request", Header: "user-agent", Value: "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36", Feature: "Chrome/40.0.2214.85 User-Agent", Weight: 0.55, Reason: "External provenance pending; this item preserves only the pinned v11a predicate."},
	}
}

func (e *Engine) matchCovenantHTTP(ch *httpChannel, m *httpMsg, path string, frame int64) {
	for _, item := range e.covenantHTTP {
		if (item.Message == "request") != m.req {
			continue
		}
		matched := false
		switch item.Kind {
		case "uri_exact":
			matched = path == item.Value
		case "header_exact":
			matched = m.hdr[item.Header] == item.Value
		case "header_contains":
			matched = strings.Contains(m.hdr[item.Header], item.Value)
		case "body_prefix":
			matched = bytes.HasPrefix(m.head, []byte(item.Value))
		case "body_contains_any":
			for _, value := range item.Values {
				if bytes.Contains(m.head, []byte(value)) {
					matched = true
					break
				}
			}
		}
		if matched {
			ch.fwAdd("Covenant", item.Feature, item.Weight, frame)
		}
	}
}

func (e *Engine) matchMerlinHTTP(ch *httpChannel, m *httpMsg, frame int64) {
	if !m.req {
		return
	}
	path, _, _ := strings.Cut(m.uri, "?")
	for _, item := range e.merlinHTTP {
		matched := false
		switch item.Kind {
		case "request_method_uri_exact":
			matched = m.method == item.Method && path == item.Value
		case "header_trim_equal_fold":
			matched = strings.EqualFold(strings.TrimSpace(m.hdr[item.Header]), item.Value)
		case "header_prefix":
			matched = strings.HasPrefix(m.hdr[item.Header], item.Value)
		case "header_exact":
			matched = m.hdr[item.Header] == item.Value
		}
		if matched {
			ch.fwAdd("Merlin", item.Feature, item.Weight, frame)
		}
	}
}

func (e *Engine) matchFrameworkDefaults(ch *httpChannel, m *httpMsg) {
	if e.covenantHTTP == nil && e.merlinHTTP == nil && e.profileErr == nil {
		profiles, err := loadFrameworkHTTPProfiles()
		e.profileErr = err
		if err == nil {
			e.covenantHTTP, e.merlinHTTP = profiles["covenant/http"], profiles["merlin/http"]
		}
	}
	if e.profileErr != nil {
		return
	}
	f := m.frame
	if m.req {
		path, query, _ := strings.Cut(m.uri, "?")
		ck := m.hdr["cookie"]
		ct := strings.TrimSpace(m.hdr["content-type"])

		e.matchCovenantHTTP(ch, m, path, f)

		// Merlin; preserve its original position between Covenant and PoshC2.
		e.matchMerlinHTTP(ch, m, f)

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

	ct := strings.TrimSpace(m.hdr["content-type"])
	e.matchCovenantHTTP(ch, m, "", f)
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

// scoreFrameworkDefaults turns accumulated features into one signal per
// framework whose combination clears fwThreshold.
func scoreFrameworkDefaults(a *acc, h *httpChannel) {
	names := make([]string, 0, len(h.fw))
	for fw := range h.fw {
		names = append(names, fw)
	}
	sort.Strings(names)
	for _, fw := range names {
		st := h.fw[fw]
		miss := 1.0
		feats := make([]string, 0, len(st.feats))
		for k, s := range st.feats {
			miss *= 1 - s
			feats = append(feats, k)
		}
		score := 1 - miss
		if score < fwThreshold {
			continue
		}
		sort.Strings(feats)
		a.add(stats.Signal{Name: "default_profile:" + strings.ToLower(strings.ReplaceAll(fw, " ", "_")), Weight: 0.95,
			Score: math.Round(score*100) / 100, Detail: fmt.Sprintf("%s default HTTP profile: %s", fw, strings.Join(feats, "; "))})
		a.frames(st.frames...)
	}
}
