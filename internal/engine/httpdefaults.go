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

func loadCovenantHTTPItems() ([]data.Item, error) {
	p, err := data.Load()
	if err != nil {
		return nil, err
	}
	return covenantHTTPItems(p)
}

func covenantHTTPItems(p data.Profiles) ([]data.Item, error) {
	if len(p.Frameworks) != 1 || p.Frameworks[0].ID != "covenant" {
		return nil, fmt.Errorf("expected only the covenant framework in the first migration slice")
	}
	fw := p.Frameworks[0]
	if len(fw.FieldGroups) != 1 {
		return nil, fmt.Errorf("expected only Covenant http field group in the first migration slice")
	}
	g, ok := fw.FieldGroups["http"]
	if !ok || g.Evidence != data.EvidenceUnknown || g.Verify || g.Source == nil || len(g.Items) != 8 {
		return nil, fmt.Errorf("Covenant http profile must contain eight registered D-07 legacy items")
	}
	return append([]data.Item(nil), g.Items...), nil
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

func (e *Engine) matchFrameworkDefaults(ch *httpChannel, m *httpMsg) {
	if e.covenantHTTP == nil && e.profileErr == nil {
		e.covenantHTTP, e.profileErr = loadCovenantHTTPItems()
	}
	if e.profileErr != nil {
		return
	}
	f := m.frame
	if m.req {
		path, query, _ := strings.Cut(m.uri, "?")
		ua, ck := m.hdr["user-agent"], m.hdr["cookie"]
		ct := strings.TrimSpace(m.hdr["content-type"])

		e.matchCovenantHTTP(ch, m, path, f)

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
