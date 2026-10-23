package engine

// WS-4 B-4.4 S2: passive HTTP tap for Cobalt Strike beacon configuration.
// One owner per response (stagerTap on httpMsg) drives the standalone
// internal/csconfig carver through a bounded admission prefilter, a feed cap,
// and exactly one finalize/release. The tap only observes response body bytes;
// it never changes HTTP parsing or FULL no-carve output. See
// docs/design/ws4-b44-engine-tap.md and OWNER_V11_2_B44_DECISIONS_20261022.md
// (weight 0.60, feed cap 4 MiB).

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"c2parser/internal/csconfig"
	"c2parser/internal/stats"
)

// streamStager enables the passive tap (always on; no CLI flag). A package var
// so tests can exercise the disabled path if ever needed.
var streamStager = true

const (
	stagerSignalName  = "cs_config:beacon_config"
	stagerFeedCap     = 4 << 20  // OD-B44-11: per-response feed budget
	stagerProbeBytes  = 1032     // max pre-admission probe (xorencoded header at 0..1023 + 8)
	stagerProbeCap    = 32       // process-wide concurrent probe buffers (AM-1)
	stagerOctetFloor  = 64 << 10 // octet-stream signal eligibility (F2)
	stagerWrapperMin  = 0x1000   // xorencoded minimum decoded patch size
	stagerWrapperMax  = 64 << 20 // sane upper bound for a wrapper size header
	stagerEvidenceCap = 128      // per attacker-string UTF-8 byte cap (D4)
	stagerWeight      = 0.60     // OD-B44-10
)

// stagerProbes bounds temporary pre-admission probe buffers process-wide.
var stagerProbes int32

type stagerState int

const (
	stUnclassified stagerState = iota
	stInspecting
	stRejected
	stFeeding
	stFinalized
)

// stagerStats are tap-level telemetry counters (verbose/sidecar only; never in
// default JSON or normal text — OD-B44-5/B-7).
type stagerStats struct {
	responses      int
	admitMZ        int
	admitOctet     int
	admitXor       int
	resourceLimit  int
	feedCapReached int
	evidenceInsuff int
	xorNoClen      int
	structValid    int
	signalEmitted  int
	notCarved      map[string]int
}

func newStagerStats() *stagerStats { return &stagerStats{notCarved: map[string]int{}} }

// stagerResult is a sufficient, structurally valid config pinned to a channel.
type stagerResult struct {
	cfg            *csconfig.Config
	frame          int64
	evidence       []string
	client, server netip.Addr
	port           uint16
}

type stagerTap struct {
	e             *Engine
	c             *tcpConn
	frame         int64
	state         stagerState
	carver        *csconfig.Carver
	prefix        []byte
	fed           int64
	probeHeld     bool
	octet         bool   // content-type is application/octet-stream
	branch        string // admission branch: "mz" | "octet" | "xor"
	bodyLen       int64
	rejectHdr     bool  // header pre-check already rejected (text / non-identity CE)
	clen          int64 // declared Content-Length (if clenOK)
	clenOK        bool
	ctype         string
	registered    bool
	countedNoClen bool
}

// newStagerTap creates the tap from the response headers (content-type /
// content-encoding / content-length pre-checks per AM-2 / OD-B44-4).
func (e *Engine) newStagerTap(c *tcpConn, m *httpMsg) *stagerTap {
	e.stagerInit()
	e.stager.responses++
	t := &stagerTap{e: e, c: c, frame: m.frame, state: stUnclassified}
	ctype := strings.ToLower(strings.TrimSpace(splitMedia(m.hdr["content-type"])))
	cenc := strings.ToLower(strings.TrimSpace(m.hdr["content-encoding"]))
	t.ctype = ctype
	t.clen, t.clenOK = contentLength(m.hdr)
	// Reject non-identity Content-Encoding (no decompression) and known text.
	// The octet-stream size skip is applied in decide(), after the MZ/xor
	// discriminators, so an MZ-at-0 body is never pre-rejected by its type.
	if cenc != "" && cenc != "identity" {
		t.rejectHdr = true
	} else if isTextMedia(ctype) {
		t.rejectHdr = true
	} else if ctype == "application/octet-stream" {
		t.octet = true
	}
	return t
}

func splitMedia(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		return ct[:i]
	}
	return ct
}

func isTextMedia(ct string) bool {
	if strings.HasPrefix(ct, "text/") {
		return true
	}
	switch ct {
	case "application/json", "application/xml", "application/javascript",
		"application/x-www-form-urlencoded", "application/ecmascript":
		return true
	}
	return false
}

func contentLength(hdr map[string]string) (int64, bool) {
	v, ok := hdr["content-length"]
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// feed drives the tap for one response body fragment (transfer-decoded bytes).
func (t *stagerTap) feed(b []byte) {
	if !streamStager || t.state == stRejected || t.state == stFinalized {
		return
	}
	t.bodyLen += int64(len(b))
	switch t.state {
	case stUnclassified:
		if t.rejectHdr {
			t.state = stRejected
			return
		}
		if !t.acquireProbe() {
			t.e.stager.resourceLimit++
			t.state = stRejected
			return
		}
		t.state = stInspecting
		// S2-1: register as soon as a probe is held, so closeStagers()
		// finalizes INSPECTING taps (and releases their probe) on the
		// ingest-error / Finish backstop paths — not only ADMITTED ones.
		t.e.registerStager(t)
		fallthrough
	case stInspecting:
		// Buffer up to the probe cap; admit() replays the whole prefix once.
		take := stagerProbeBytes - len(t.prefix)
		if take > len(b) {
			take = len(b)
		}
		if take < 0 {
			take = 0
		}
		t.prefix = append(t.prefix, b[:take]...)
		t.decide(false)
		// If this fragment triggered admission, the prefix (incl. b[:take])
		// was fed in admit(); feed the remainder of this fragment so no body
		// byte is dropped (the admission-boundary gap bug).
		if t.state == stFeeding && take < len(b) {
			t.feedBytes(b[take:])
		}
	case stFeeding:
		t.feedBytes(b)
	}
}

// feedBytes streams body bytes to the admitted carver, enforcing the 4 MiB
// per-response feed cap (OD-B44-11).
func (t *stagerTap) feedBytes(b []byte) {
	if t.state != stFeeding || len(b) == 0 {
		return
	}
	t.fed += int64(len(b))
	if t.fed > stagerFeedCap {
		t.e.stager.feedCapReached++
		t.finalizeFeedCap()
		return
	}
	t.carver.Feed(b)
}

// decide resolves admission once there is enough prefix (or at finalize).
func (t *stagerTap) decide(final bool) {
	if t.state != stInspecting {
		return
	}
	// Discriminators first (MZ@0, then a validated xorencoded header), so an
	// MZ/xor body is admitted regardless of its declared content type/length.
	branch := ""
	switch {
	case len(t.prefix) >= 2 && t.prefix[0] == 'M' && t.prefix[1] == 'Z':
		branch = "mz"
	case t.xorHeader():
		branch = "xor"
	case t.octet && (!t.clenOK || t.clen >= stagerOctetFloor):
		// Generic typed binary: provisional carver; signal gated on >= 64 KiB.
		branch = "octet"
	default:
		// MZ needs 2 bytes and xor up to 1032; wait for more, else reject.
		if final || len(t.prefix) >= stagerProbeBytes {
			t.releaseProbe()
			t.state = stRejected
		}
		return
	}
	t.admit(branch)
}

// xorHeader scans offsets 0..1023 for a valid xorencoded size header. A real
// wrapper's decoded size equals the bytes that follow it: Content-Length ==
// off + 8 + decoded_size (+ a trailer within the carver's 256-byte slack). That
// exact tie to the body length makes a random 8-byte window an almost-never
// match, so the prefilter admits essentially only genuine wrappers; the carver
// re-validates the decoded stream, containment and trailer at Result(). A
// wrapper requires a declared Content-Length; without one the xor branch is not
// taken (MZ / octet-stream still apply).
func (t *stagerTap) xorHeader() bool {
	if !t.clenOK {
		// S2-2: a plausible wrapper size header with no declared length is not
		// admitted (the size can't be tied to the body); count it once.
		if !t.countedNoClen && t.plausibleXorHeader() {
			t.e.stager.xorNoClen++
			t.countedNoClen = true
		}
		return false
	}
	if t.clen < stagerWrapperMin {
		return false
	}
	p := t.prefix
	limit := len(p) - 8
	if limit > 1023 {
		limit = 1023
	}
	for off := 0; off <= limit; off++ {
		nonce := binary.LittleEndian.Uint32(p[off : off+4])
		enc := binary.LittleEndian.Uint32(p[off+4 : off+8])
		size := int64(enc ^ nonce)
		if size < stagerWrapperMin || size > stagerWrapperMax {
			continue
		}
		slack := t.clen - int64(off) - 8 - size
		if slack >= 0 && slack <= 256 {
			return true
		}
	}
	return false
}

func (t *stagerTap) admit(branch string) {
	t.releaseProbe()
	t.carver = csconfig.New(csconfig.Options{VersionMap: t.e.stagerVersionMap, Limiter: t.e.stagerLimiter})
	if t.carver.Reason() == csconfig.ReasonResourceLimit {
		t.e.stager.resourceLimit++
		t.carver = nil
		t.state = stRejected
		return
	}
	switch branch {
	case "mz":
		t.e.stager.admitMZ++
	case "octet":
		t.e.stager.admitOctet++
	case "xor":
		t.e.stager.admitXor++
	}
	t.branch = branch
	t.state = stFeeding
	t.e.registerStager(t)
	// replay the retained prefix exactly once, then stream.
	t.fed = int64(len(t.prefix))
	if t.fed > stagerFeedCap {
		t.e.stager.feedCapReached++
		t.finalizeFeedCap()
		return
	}
	t.carver.Feed(t.prefix)
	t.prefix = nil
}

func (t *stagerTap) finalizeFeedCap() {
	if t.carver != nil {
		t.carver.Close()
	}
	t.e.deregisterStager(t)
	t.state = stFinalized
}

// finalize is the single idempotent terminal path (B-1). emit is false on
// truncation/teardown.
func (t *stagerTap) finalize(emit bool) {
	switch t.state {
	case stFinalized, stRejected:
		if t.carver != nil {
			t.carver.Close()
			t.carver = nil
		}
		t.releaseProbe()
		t.e.deregisterStager(t)
		t.state = stFinalized
		return
	case stUnclassified:
		t.releaseProbe()
		t.e.deregisterStager(t)
		t.state = stFinalized
		return
	case stInspecting:
		// decide at end of stream; if still undecided -> reject.
		t.decide(true)
		if t.state != stFeeding {
			t.releaseProbe()
			if t.carver != nil {
				t.carver.Close()
				t.carver = nil
			}
			t.e.deregisterStager(t)
			t.state = stFinalized
			return
		}
	}
	// stFeeding
	t.e.deregisterStager(t)
	if !emit {
		t.carver.Close()
		t.state = stFinalized
		return
	}
	cfg, ok := t.carver.Result()
	if ok {
		t.e.stager.structValid++
		if t.branch == "octet" && t.bodyLen < stagerOctetFloor {
			// not signal-eligible: a small octet-stream body.
			t.e.stager.notCarved["octet_below_floor"]++
		} else if ev, suff := stagerSufficient(cfg); suff {
			t.e.recordStagerConfig(t.c, &stagerResult{cfg: cfg, frame: t.frame, evidence: ev})
			t.e.stager.signalEmitted++
		} else {
			t.e.stager.evidenceInsuff++
		}
	} else {
		t.e.stager.notCarved[string(t.carver.Reason())]++
	}
	t.carver.Close()
	t.state = stFinalized
}
func (t *stagerTap) plausibleXorHeader() bool {
	p := t.prefix
	limit := len(p) - 8
	if limit > 1023 {
		limit = 1023
	}
	for off := 0; off <= limit; off++ {
		nonce := binary.LittleEndian.Uint32(p[off : off+4])
		enc := binary.LittleEndian.Uint32(p[off+4 : off+8])
		size := int64(enc ^ nonce)
		if size >= stagerWrapperMin && size <= stagerWrapperMax {
			return true
		}
	}
	return false
}

func (t *stagerTap) acquireProbe() bool {
	if atomic.AddInt32(&stagerProbes, 1) > stagerProbeCap {
		atomic.AddInt32(&stagerProbes, -1)
		return false
	}
	t.probeHeld = true
	return true
}

func (t *stagerTap) releaseProbe() {
	if t.probeHeld {
		atomic.AddInt32(&stagerProbes, -1)
		t.probeHeld = false
	}
}

// stagerSufficient applies OD-B44-3 and builds the fixed-order evidence (D4).
func stagerSufficient(cfg *csconfig.Config) ([]string, bool) {
	recognized := 0
	hasTiming := false
	var sleep, jitter, submituri, useragent, host, pipename string
	for _, s := range cfg.Settings {
		if s.Name == "PUBKEY" || strings.HasPrefix(s.Name, "SETTING_") || s.Name == "" {
			continue
		}
		recognized++
		switch s.Name {
		case "SLEEPTIME":
			hasTiming = true
			if s.HasNumber {
				sleep = strconv.FormatUint(s.Number, 10)
			}
		case "JITTER":
			hasTiming = true
			if s.HasNumber {
				jitter = strconv.FormatUint(s.Number, 10)
			}
		case "SUBMITURI":
			submituri = sanitizeEvidence(string(s.Raw))
		case "USERAGENT":
			useragent = sanitizeEvidence(string(s.Raw))
		case "HOST_HEADER":
			host = sanitizeEvidence(string(s.Raw))
		case "PIPENAME":
			pipename = sanitizeEvidence(string(s.Raw))
		}
	}
	if recognized < 2 || !hasTiming {
		return nil, false
	}
	var ev []string
	if sleep != "" {
		ev = append(ev, "Sleep: "+sleep)
	}
	if jitter != "" {
		ev = append(ev, "Jitter: "+jitter)
	}
	if submituri != "" {
		ev = append(ev, "SubmitURI: "+submituri)
	}
	if useragent != "" {
		ev = append(ev, "UserAgent: "+useragent)
	}
	if host != "" {
		ev = append(ev, "HostHeader: "+host)
	}
	if pipename != "" {
		ev = append(ev, "Pipename: "+pipename)
	}
	if cfg.VersionAnnotation != "" {
		ev = append(ev, "Version: "+sanitizeEvidence(cfg.VersionAnnotation))
	}
	if cfg.XorEncoded {
		ev = append(ev, "Xorencoded: yes")
	} else {
		ev = append(ev, "Xorencoded: no")
	}
	return ev, true
}

// sanitizeEvidence caps at 128 UTF-8 bytes and escapes control chars / invalid
// UTF-8 (D4). No raw bytes, keys, PUBKEY or watermark ever reach here.
func sanitizeEvidence(s string) string {
	if len(s) > stagerEvidenceCap {
		s = s[:stagerEvidenceCap]
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, "\\x%02x", s[i])
			i++
			continue
		}
		if r < 0x20 || r == 0x7f {
			fmt.Fprintf(&b, "\\x%02x", byte(r))
		} else {
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// c2KeyForConn returns the HTTP C2 finding key for this response's channel.
func stagerKey(c *tcpConn) (netip.Addr, netip.Addr, uint16, string) {
	return c.client.Addr(), c.server.Addr(), c.server.Port(), c2Key(c.client.Addr(), c.server.Addr(), c.server.Port())
}

// scoreStager folds each sufficient config into its HTTP C2 finding, or builds
// a deterministic config finding when no channel finding exists. The signal and
// every evidence line / frame go through evidenceFrom/framesFrom with
// cs_config:beacon_config (B-6), so BLIND drops them and records the drop.
func (e *Engine) scoreStager(sc *scorer) {
	if len(e.stagerConfigs) == 0 {
		return
	}
	keys := make([]string, 0, len(e.stagerConfigs))
	for k := range e.stagerConfigs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		r := e.stagerConfigs[key]
		sig := stats.Signal{Name: stagerSignalName, Weight: stagerWeight, Score: 1.0,
			Detail: "passive Cobalt Strike beacon configuration recovered from an HTTP response body"}
		a := sc.accs[key]
		if a == nil || a.f.Category != CatC2 {
			title := fmt.Sprintf("HTTP response contains a passive beacon configuration (Cobalt Strike) (%s → %s)", r.client, r.server)
			a = sc.get(key, CatC2, title, r.client, r.server, time.Time{}, time.Time{})
		}
		a.add(sig)
		for _, ev := range r.evidence {
			a.evidenceFrom(stagerSignalName, "%s", ev)
		}
		a.framesFrom(stagerSignalName, r.frame)
	}
}

// loadProbes reports the current probe-slot count (tests only).
func loadProbes() int32 { return atomic.LoadInt32(&stagerProbes) }

// StagerCounts exposes tap telemetry as an evaluation sidecar (OD-B44-5/B-7).
// It is NOT part of Result, default JSON, or normal text output; callers that
// want it (verbose text / eval tooling) read it from the engine explicitly.
func (e *Engine) StagerCounts() map[string]int {
	m := map[string]int{}
	if e.stager == nil {
		return m
	}
	s := e.stager
	m["responses"] = s.responses
	m["admit_mz"] = s.admitMZ
	m["admit_octet_stream"] = s.admitOctet
	m["admit_xorencoded"] = s.admitXor
	m["resource_limit"] = s.resourceLimit
	m["feed_cap_reached"] = s.feedCapReached
	m["evidence_insufficient"] = s.evidenceInsuff
	m["xor_unadmitted_no_clen"] = s.xorNoClen
	m["structurally_valid"] = s.structValid
	m["signal_emitted"] = s.signalEmitted
	for r, n := range s.notCarved {
		m["not_carved:"+r] = n
	}
	return m
}
