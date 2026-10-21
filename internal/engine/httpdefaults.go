package engine

import (
	"bytes"
	"fmt"
	"math"
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

// registeredFrameworkHTTPItems is closed to reviewed framework/group identities.
// YAML holds predicate values; independent frozen tables are the exact-value oracle.
func registeredFrameworkHTTPItems(p data.Profiles) (map[string][]data.Item, error) {
	if p.SchemaVersion != 1 || len(p.Frameworks) != 3 {
		return nil, fmt.Errorf("UNAUTHORIZED_PROFILE_GROUP: expected exactly three registered HTTP groups")
	}
	type spec struct {
		id, sourceID, citation, reason, sourceLoc, prefix string
		ids, locs, kinds, dirs                            []string
	}
	rev := "425897e8c36005e001e6f6254ede16117194f9d2"
	specs := []spec{
		{"covenant", "v11a-covenant-http-legacy-code", "Existing Covenant HTTP predicates in the pinned v11a implementation; this is code provenance, not external corroboration.", "External provenance pending; this item-level register preserves only existing v11a behavior.", "matchFrameworkDefaults", "B33-D07-COV-HTTP-", []string{"covenant-http-uri-index", "covenant-http-uri-docs", "covenant-http-uri-test", "covenant-http-user-agent", "covenant-http-cookie", "covenant-http-post-template", "covenant-http-server", "covenant-http-response-template"}, []string{"103-104", "103-104", "103-104", "106-107", "109-110", "112-113", "156-157", "159-160"}, []string{"uri_exact", "uri_exact", "uri_exact", "header_exact", "header_contains", "body_prefix", "header_exact", "body_contains_any"}, []string{"request", "request", "request", "request", "request", "request", "response", "response"}},
		{"merlin", "v11a-merlin-http-legacy-code", "Existing Merlin HTTP predicates in the pinned v11a implementation; code provenance only, external provenance pending.", "External provenance pending; item-level records preserve only existing v11a behavior.", "matchFrameworkDefaults", "B33-D07-MER-HTTP-", []string{"merlin-http-post-root", "merlin-http-content-type", "merlin-http-authorization-prefix", "merlin-http-user-agent"}, []string{"117-118", "120-121", "123-124", "126-127"}, []string{"request_method_uri_exact", "header_trim_equal_fold", "header_prefix", "header_exact"}, []string{"request", "request", "request", "request"}},
		{"poshc2", "v11a-poshc2-http-legacy-code", "Existing PoshC2 HTTP predicates in the pinned v11a implementation; this is code provenance, not external corroboration.", "External provenance pending; these items carry forward only pinned v11a behavior.", "matchFrameworkDefaults", "B33-D07-POSH-HTTP-", []string{"poshc2-http-cookie-session-prefix", "poshc2-http-server-raw-apache-space", "poshc2-http-http10-content-type-case", "poshc2-http-iis-footer", "poshc2-http-apache-debian-footer", "poshc2-http-slack-app-marker"}, []string{"131-132", "163-164", "166-167", "169-170", "172-173", "175-176"}, []string{"cookie_prefix", "response_server_raw_exact", "response_proto_and_raw_header_name", "body_contains", "body_contains", "body_contains"}, []string{"request", "response", "response", "response", "response", "response"}},
	}
	out := make(map[string][]data.Item, 3)
	seenID, seenDebt := map[string]bool{}, map[string]bool{}
	for fi, fw := range p.Frameworks {
		sp := specs[fi]
		if fw.ID != sp.id || len(fw.Aliases) != 0 || len(fw.FieldGroups) != 1 {
			return nil, fmt.Errorf("UNAUTHORIZED_PROFILE_GROUP: registry order/shape mismatch")
		}
		g, ok := fw.FieldGroups["http"]
		if !ok || g.Evidence != data.EvidenceUnknown || g.Verify || g.Source == nil || len(g.Items) != len(sp.ids) {
			return nil, fmt.Errorf("PROFILE_ITEM_SET_MISMATCH: %s/http status or count", fw.ID)
		}
		if g.Source.ID != sp.sourceID || g.Source.Citation != sp.citation || g.Source.Revision != rev || g.Source.Locator != "repo@"+rev+":internal/engine/httpdefaults.go:"+sp.sourceLoc || g.Reason != sp.reason {
			return nil, fmt.Errorf("PROFILE_SOURCE_MISMATCH: %s/http", fw.ID)
		}
		for i, it := range g.Items {
			if it.ID != sp.ids[i] || it.DebtID != fmt.Sprintf("%s%03d", sp.prefix, i+1) || it.Locator != "repo@"+rev+":internal/engine/httpdefaults.go:"+sp.locs[i] || it.Kind != sp.kinds[i] || it.Message != sp.dirs[i] {
				return nil, fmt.Errorf("PROFILE_ITEM_SET_MISMATCH: %s/http item %d", fw.ID, i)
			}
			if ((fw.ID == "poshc2" || fw.ID == "merlin") && it.Reason == "") || seenID[it.ID] || seenDebt[it.DebtID] {
				return nil, fmt.Errorf("PROFILE_ITEM_SET_MISMATCH: missing PoshC2 reason or duplicate identity")
			}
			seenID[it.ID] = true
			seenDebt[it.DebtID] = true
		}
		out[fw.ID+"/http"] = append([]data.Item(nil), g.Items...)
	}
	return out, nil
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

func (e *Engine) matchPoshHTTP(ch *httpChannel, m *httpMsg, frame int64) error {
	for _, item := range e.poshHTTP {
		if (item.Message == "request") != m.req {
			continue
		}
		matched := false
		switch item.Kind {
		case "cookie_prefix":
			matched = m.req && strings.HasPrefix(m.hdr[item.Header], item.Value)
		case "response_server_raw_exact":
			matched = !m.req && m.serverRaw == item.Value
		case "response_proto_and_raw_header_name":
			matched = !m.req && m.proto == item.Value && hasHeaderName(m, item.Header)
		case "body_contains":
			matched = !m.req && bytes.Contains(m.head, []byte(item.Value))
		default:
			return fmt.Errorf("POSHC2_UNSUPPORTED_KIND: %s", item.Kind)
		}
		if matched {
			ch.fwAdd("PoshC2", item.Feature, item.Weight, frame)
		}
	}
	return nil
}

func (e *Engine) matchFrameworkDefaults(ch *httpChannel, m *httpMsg) {
	if e.covenantHTTP == nil && e.merlinHTTP == nil && e.poshHTTP == nil && e.profileErr == nil {
		profiles, err := loadFrameworkHTTPProfiles()
		e.profileErr = err
		if err == nil {
			e.covenantHTTP, e.merlinHTTP, e.poshHTTP = profiles["covenant/http"], profiles["merlin/http"], profiles["poshc2/http"]
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

		// PoshC2, in the pinned v11a order.
		if err := e.matchPoshHTTP(ch, m, f); err != nil {
			e.profileErr = err
			return
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
	// PoshC2 (CPython http.server underneath), preserving pinned order.
	if err := e.matchPoshHTTP(ch, m, f); err != nil {
		e.profileErr = err
		return
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
