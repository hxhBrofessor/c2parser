package engine

import (
	"fmt"
	"regexp"
	"strings"

	"c2parser/internal/stats"
)

// URI-shape families (v11a N2). Neutral, attribution-free descriptions of
// how a client's request paths look, as a small table of Go constants
// (v11b moves it into the profile YAML):
//
//	checksum8-x86  4-char [A-Za-z0-9] path whose byte sum ≡ 92 (mod 256)
//	checksum8-x64  … ≡ 93 (the Metasploit / Cobalt Strike stager check)
//	word-dot-ext   /<word>.<ext> with ext in a small static-file set,
//	               polled: most requests of a channel, ≤ 3 distinct URIs
//	fixed-uri      every request of a beacon-timed channel to one URI
//
// The Cobalt Strike default-profile feature in httpdefaults.go keeps its
// own emit ("stager URI … (checksum8 = N)", 0.35) byte for byte; the
// checksum8 families here reuse checksum8() and add the neutral shape.
//
// x86 rule decision (v11a): the repo applies the 4-char rule to x86 as
// well as x64; the dissect.cobaltstrike reference applies it to x64 only
// (x86 = checksum8 == 92 at any length). The stricter rule is kept: with no
// length rule 1 in 256 of *all* benign paths would match, against 1 in 128
// of 4-char alnum paths now, and nothing in the lab or the corpus needs
// the looser rule. Revisit only with a measured FP budget.
//
// Scoring: uri_shape:* weight 0.3, family http_client_quirks, except
// fixed-uri (timing family, stats.FixedURITimingFamily). A bare checksum8
// hit scores 0.5 (contribution 0.15, below "low" on its own); a hit whose
// response was a ≥ 64 KB non-HTML download (a staged payload) scores 1.
// None can make a timing beacon escape its cap: see timingPlusURIShape.

const (
	uriShapeWeight  = 0.3
	stagerMinBytes  = 64 << 10
	wordDotMinFrac  = 0.8
	wordDotMaxURIs  = 3
	uriShapeMinReqs = 5
)

var wordDotExtRe = regexp.MustCompile(`^/[a-z]{3,16}\.(php|asp|aspx|jsp|gif|png|jpg|ico|js|css|rss|xml|htm|html)$`)

// uriShapeOf classifies one request path (no query) into a per-request
// family, or "".
func uriShapeOf(path string) string {
	if sum, ok := checksum8(path); ok {
		if sum == 92 {
			return "checksum8-x86"
		}
		return "checksum8-x64"
	}
	if wordDotExtRe.MatchString(path) {
		return "word-dot-ext"
	}
	return ""
}

// uriShapeStats is per-channel URI-shape state.
type uriShapeStats struct {
	hits    map[string]int    // requests per family
	example map[string]string // first path per family
	staged  map[string]int    // checksum8 hits answered by a staged download
}

// noteURIShape records a request's shape; c.stagerPend remembers a
// checksum8 request until its response arrives.
func (ch *httpChannel) noteURIShape(c *tcpConn, m *httpMsg) {
	if !m.req {
		if fam := c.stagerPend; fam != "" {
			c.stagerPend = ""
			ct := strings.ToLower(m.hdr["content-type"])
			if m.bodyLen >= stagerMinBytes && !strings.HasPrefix(ct, "text/") && ch.shapes != nil {
				ch.shapes.staged[fam]++
			}
		}
		return
	}
	path, _, _ := strings.Cut(m.uri, "?")
	fam := uriShapeOf(path)
	c.stagerPend = ""
	if fam == "" {
		return
	}
	if ch.shapes == nil {
		ch.shapes = &uriShapeStats{hits: map[string]int{}, example: map[string]string{}, staged: map[string]int{}}
	}
	ch.shapes.hits[fam]++
	if _, ok := ch.shapes.example[fam]; !ok {
		ch.shapes.example[fam] = strings.Clone(path)
	}
	if strings.HasPrefix(fam, "checksum8-") && m.method == "GET" {
		c.stagerPend = fam
	}
}

// scoreURIShapes adds the uri_shape:* signals for one HTTP channel.
// timing are the channel's request-timing signals.
//
// fixed-uri is emitted under -timing v2 only, and only when a timing
// signal really contributes. It is timing-derived: v2 folds it into the
// timing family (max + damped second), while v1 combines every signal by
// plain noisy-OR with no families, so there it would count the timing
// evidence twice. Measured on the corpus before this rule: the benign
// Prometheus scrape in benign-models rose 0.75 → 0.83 under v1 (high,
// 0.02 short of critical) and a 10-request apt poll with no timing signal
// appeared at 0.30. v1 output stays byte-identical.
func scoreURIShapes(a *acc, h *httpChannel, timing []stats.Signal, v2 bool, minBeacon int) {
	if s := h.shapes; s != nil {
		for _, fam := range []string{"checksum8-x86", "checksum8-x64"} {
			n := s.hits[fam]
			if n == 0 {
				continue
			}
			score, how := 0.5, ""
			if s.staged[fam] > 0 {
				score, how = 1, fmt.Sprintf("; %d answered by a ≥ %d KB non-text download", s.staged[fam], stagerMinBytes>>10)
			}
			sum, _ := checksum8(s.example[fam])
			a.add(stats.Signal{Name: "uri_shape:" + fam, Weight: uriShapeWeight, Score: score,
				Detail: fmt.Sprintf("%d request(s) to a 4-char path whose checksum8 is %d, e.g. %s%s", n, sum, s.example[fam], how)})
		}
		if n := s.hits["word-dot-ext"]; h.requests >= uriShapeMinReqs && h.uris.len() <= wordDotMaxURIs {
			if frac := float64(n) / float64(h.requests); frac >= wordDotMinFrac {
				a.add(stats.Signal{Name: "uri_shape:word-dot-ext", Weight: uriShapeWeight, Score: frac,
					Detail: fmt.Sprintf("%d/%d requests poll /<word>.<ext> static-file paths (%d distinct), e.g. %s", n, h.requests, h.uris.len(), s.example["word-dot-ext"])})
			}
		}
	}
	timed := false
	for _, sg := range timing {
		timed = timed || stats.FamilyOf(sg.Name) == "timing" && sg.Contribution() >= negligible
	}
	if v2 && timed && h.requests >= minBeacon && h.uris.len() == 1 {
		a.add(stats.Signal{Name: "uri_shape:fixed-uri", Weight: uriShapeWeight, Score: 1,
			Detail: fmt.Sprintf("all %d requests go to one URI (%s) on a beacon cadence", h.requests, topKey(h.uris.Map()))})
	}
}

// uriShapeCapTiming enables the timing+URI-shape cap (mutation hook).
var uriShapeCapTiming = true

// timingPlusURIShape: the evidence is timing (with session shape) plus
// uri_shape:* signals and nothing else. A URI shape describes how a
// periodic client addresses its server; on a fleet / poller / scheduler
// series it must not lift the finding above the timing-only cap (the
// v10a.1 defect class), whatever family it maps to. Mirrors
// timingPlusRecon.
func timingPlusURIShape(sigs []stats.Signal) bool {
	shape := false
	var rest []stats.Signal
	for _, sg := range sigs {
		if strings.HasPrefix(sg.Name, "uri_shape:") {
			shape = shape || sg.Contribution() >= negligible
			continue
		}
		rest = append(rest, sg)
	}
	return shape && onlyTiming(rest)
}
