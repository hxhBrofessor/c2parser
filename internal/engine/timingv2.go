package engine

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"

	"c2parser/internal/stats"
)

// Timing adapter (c2parser v8, spec Q1/Q2.5). Every beacon-scoring call site
// goes through e.beacon, so "-timing v1|v2" is one switch:
//
//   - v1 (default): stats.ScoreBeacon + beaconSignal, byte-for-byte as v6.
//   - v2: event-model routing, stats.AnalyzeTiming with the refusal ladder,
//     dispersion vs. generated null quantiles as the only timing evidence,
//     everything else as annotations; v1 and v2 scores both land in
//     Result.TimingSeries for evaluation.

// Event models (spec Q1.1).
const (
	ModelPerRequest = "per_request"
	ModelHeartbeat  = "persistent_heartbeat"
	ModelP2P        = "p2p"
	ModelPush       = "push_or_saas"
)

// TimingSeries is one scored (or refused) event series in v2 mode.
type TimingSeries struct {
	Site       string        `json:"site"`
	Key        string        `json:"key"`
	EventModel string        `json:"event_model"`
	V1Score    *float64      `json:"v1_score,omitempty"`
	V2Score    float64       `json:"v2_score"`
	Refused    string        `json:"refused,omitempty"`
	Timing     *stats.Timing `json:"timing,omitempty"`
	times      []float64     // for the eval harness's baselines
}

// Times returns the series' event times (seconds from capture start).
func (t TimingSeries) Times() []float64 { return t.times }

// Keep-alive-shaped series use the call site's normal timing weight at
// every period (v9 rev 2 Phase 0.1: single-host tiny-burst beacons must
// score ≥ 0.6). Benign keep-alive fleets are held down by the finding-level
// fleet/scheduler cap instead of a lower weight here.

// knownHeartbeats are transport keep-alive cadences (seconds) that persistent
// sessions show regardless of agent sleep: QUIC/yamux 15–30 s, 2-min pings.
var knownHeartbeats = []float64{15, 30, 120}

// beacon scores one event series. strength is what call sites gate on (v1:
// Beacon.Score; v2: the dispersion evidence).
func (e *Engine) beacon(site, key, model string, times, sizes []float64, p stats.BeaconParams, weight float64, what string) (sigs []stats.Signal, strength float64) {
	b, ok := stats.ScoreBeacon(times, sizes, p)
	if !e.cfg.TimingV2 {
		if !ok {
			return nil, 0
		}
		return []stats.Signal{beaconSignal(b, weight, what)}, b.Score
	}
	ts := TimingSeries{Site: site, Key: key, EventModel: model, times: stats.Sorted(times)}
	if ok {
		v := round2(b.Score)
		ts.V1Score = &v
	}
	defer func() { e.timingSeries = append(e.timingSeries, ts) }()

	switch model {
	case ModelP2P, ModelPush:
		// Peer-to-peer legs follow their parent; push channels are bursty by
		// construction. Timing is refused, not scored.
		ts.Refused = "event_model:" + model
		return nil, 0
	}
	t := stats.AnalyzeTiming(times, stats.TimingParams{CaptureEnd: e.rel(e.last)})
	ts.Timing = &t
	note := ""
	if model == ModelHeartbeat {
		// v9 Phase 0.1: keep-alive-shaped series get one dispersion weight
		// at every period; a cadence match to a transport keep-alive is an
		// annotation, not a separate low-weight path (v8b had a cliff:
		// 0.25 at 30 s vs 0.65 at 45 s). Timing can't separate real
		// keep-alives from tiny-poll C2; other families decide the rest.
		what += " (keep-alive-shaped session)"
		for _, hb := range knownHeartbeats {
			if math.Abs(t.PeriodSec-hb) <= 0.1*hb {
				note = fmt.Sprintf("; period matches a transport keep-alive interval (%.0f s)", hb)
			}
		}
	}
	s, d := t.DispersionEvidence()
	if s <= 0 {
		return nil, 0
	}
	detail := d + note + "; " + t.Describe()
	if t.Anchored {
		// Anchored grid + random delay is the systemd/Defender/apt shape:
		// a mild negative that reduces, never zeroes.
		s *= 0.7
		detail += " (×0.7: anchored-scheduler shape)"
	}
	ts.V2Score = round2(s)
	sigs = append(sigs, stats.Signal{Name: "timing_dispersion", Weight: weight, Score: s, Detail: fmt.Sprintf("%s: %s", what, detail)})
	if t.TaskingBursts >= 2 {
		sigs = append(sigs, stats.Signal{Name: "timing_interactive_on_periodic", Weight: 0.3, Score: stats.Clamp01(float64(t.TaskingBursts) / 5),
			Detail: fmt.Sprintf("%d bursts of rapid traffic on an otherwise periodic channel (operator activity)", t.TaskingBursts)})
	}
	return sigs, s
}

// channelModel classifies a generic TCP/UDP channel (spec Q1.1, v8a review
// finding 1). persistent_heartbeat needs positive transport evidence:
//
//   - QUIC (packet cadence is the transport's, not the agent's);
//   - keep-alive-shaped bursts: tiny (≤ keepaliveMaxBytes) and near-constant
//     in BOTH directions — yamux/QUIC/TLS/WireGuard pings — on a UDP flow or
//     a long-held TCP session.
//
// A long-lived connection that carries request/response turns with
// application-sized, variable payloads (WinINet/WinHTTP keep-alive HTTPS
// beacons) stays per_request. mTLS-like TLS 1.3 (CertificateRequest + no
// ALPN) is not used: in TLS 1.3 the CertificateRequest is encrypted, so it
// can't be observed passively; the keep-alive shape covers those sessions.
func channelModel(ch *channel) string {
	if ch.quic {
		return ModelHeartbeat
	}
	if keepaliveShaped(ch) && (ch.key.proto == "udp" || longHeld(ch)) {
		return ModelHeartbeat
	}
	return ModelPerRequest
}

const keepaliveMaxBytes = 100

func longHeld(ch *channel) bool {
	n := len(ch.burstT)
	if ch.conns == 0 || ch.conns > 3 || n < 10 {
		return false
	}
	span := ch.burstT[n-1] - ch.burstT[0]
	return span > 0 && ch.maxConnSec >= 0.5*span
}

// keepaliveShaped: median burst ≤ keepaliveMaxBytes and MAD/median ≤ 0.15
// in each direction (medians ignore the one-off handshake bursts). A
// direction with no bursts at all (one-way keep-alives) passes.
func keepaliveShaped(ch *channel) bool {
	if len(ch.burstS) < 10 {
		return false
	}
	ok := func(x []float64) bool {
		if len(x) == 0 {
			return true
		}
		med := stats.Quantile(stats.Sorted(x), .5)
		return med > 0 && med <= keepaliveMaxBytes && stats.MAD(x, med)/med <= 0.15
	}
	return ok(ch.burstS) && ok(ch.inBurstS)
}

// ---------------------------------------------------------------- flow keys

var timeZero time.Time

// scoreTimingRollups builds name-keyed series (spec Q1.2) in v2 mode:
//
//	K1 = (client, name): HTTP Host / TLS SNI across server IPs and ports;
//	K2 = (client, server IP) across ports, for unnamed traffic.
//
// Round-robin redirectors split one beacon over k IPs (k× the per-IP gap);
// the K1 series restores the real period. Evidence from a K1/K2 series is
// added to every member channel's finding.
// k1Rollup merges K1 groups into one finding (v9c 2.1); false restores
// v9b's per-IP findings (mutation / comparison tests).
var k1Rollup = true

// rollMember is one per-IP channel inside a K1/K2 group.
type rollMember struct {
	key   string
	title string
	cl    netip.Addr
	sv    netip.Addr
}

func (e *Engine) scoreTimingRollups(sc *scorer) {
	type member = rollMember
	type group struct {
		times   []float64
		servers map[netip.Addr]bool
		ports   map[uint16]bool
		members []member
	}
	k1 := map[string]*group{}
	k2 := map[string]*group{}
	add := func(m map[string]*group, gk string, t []float64, srv netip.Addr, port uint16, mem member) {
		g := m[gk]
		if g == nil {
			g = &group{servers: map[netip.Addr]bool{}, ports: map[uint16]bool{}}
			m[gk] = g
		}
		g.times = append(g.times, t...)
		g.servers[srv] = true
		g.ports[port] = true
		g.members = append(g.members, mem)
	}
	httpConn := map[string]bool{}
	for _, h := range e.httpOrder {
		k := h.key
		if len(h.reqT) == 0 {
			continue
		}
		key := c2Key(k.client, k.server, k.port)
		httpConn[key] = true
		mem := member{key, fmt.Sprintf("HTTP channel %s → %s:%d (Host: %s)", k.client, k.server, k.port, k.host), k.client, k.server}
		if _, err := netip.ParseAddr(strings.Trim(strings.Split(k.host, ":")[0], "[]")); err != nil && k.host != "" {
			add(k1, "K1|"+k.client.String()+"|"+strings.Split(k.host, ":")[0], h.reqT, k.server, k.port, mem)
		}
	}
	for _, ch := range e.chOrder {
		k := ch.key
		key := c2Key(k.client, k.server, k.port)
		if httpConn[key] || len(ch.burstT) == 0 || !e.pairEligible(k.client, k.server) || (channelModel(ch) != ModelPerRequest && !ch.quic) {
			continue
		}
		mem := member{key, fmt.Sprintf("Beaconing %s → %s:%d/%s", k.client, k.server, k.port, k.proto), k.client, k.server}
		if t := ch.tls; t != nil && t.sni.len() > 0 {
			sni, _ := topCount(t.sni.Map())
			add(k1, "K1|"+k.client.String()+"|"+sni, ch.burstT, k.server, k.port, mem)
			continue
		}
		add(k2, "K2|"+k.client.String()+"|"+k.server.String(), ch.burstT, k.server, k.port, mem)
	}
	score := func(m map[string]*group, need func(*group) bool, label string) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, gk := range keys {
			g := m[gk]
			if !need(g) {
				continue
			}
			sort.Float64s(g.times)
			sigs, _ := e.beacon("rollup", gk, ModelPerRequest, g.times, nil, e.cfg.Beacon, 0.7,
				fmt.Sprintf("%s series over %d server IPs / %d ports", label, len(g.servers), len(g.ports)))
			if len(sigs) == 0 {
				continue
			}
			if label == "K1" && k1Rollup {
				e.rollupK1(sc, gk, g.members, len(g.servers), len(g.ports), len(g.times), sigs)
				continue
			}
			for _, mem := range g.members {
				a := sc.get(mem.key, CatC2, mem.title, mem.cl, mem.sv, timeZero, timeZero)
				for _, s := range sigs {
					s.Name += "_" + strings.ToLower(label)
					a.add(s)
				}
			}
		}
	}
	score(k1, func(g *group) bool { return len(g.servers) >= 2 || len(g.ports) >= 2 }, "K1")
	score(k2, func(g *group) bool { return len(g.ports) >= 2 }, "K2")
}

// rollupK1 replaces the per-IP findings of one (client, name) K1 group —
// a beacon spread over redirector IPs or ports behind one SNI / Host — with
// a single finding (v9c 2.1). The K1 series is its timing evidence; every
// member's own signals carry over (strongest per name), and each member is
// listed in the evidence. The per-IP findings are dropped.
func (e *Engine) rollupK1(sc *scorer, gk string, members []rollMember, nServers, nPorts, nEvents int, sigs []stats.Signal) {
	parts := strings.SplitN(gk, "|", 3) // K1|client|name
	if len(parts) != 3 || len(members) == 0 {
		return
	}
	name := parts[2]
	title := fmt.Sprintf("Beaconing %s → %s (%d server IPs, %d ports)", members[0].cl, name, nServers, nPorts)
	ra := sc.get("k1|"+parts[1]+"|"+strings.ToLower(name), CatC2, title, members[0].cl, members[0].sv, timeZero, timeZero)
	ra.f.Server, ra.f.ServerNames, ra.namesSet = name, nil, true // the destination is the name, not one member's IP
	for _, s := range sigs {
		s.Name += "_k1"
		ra.add(s)
	}
	seen := map[string]bool{}
	var first, last string
	for _, mem := range members {
		if seen[mem.key] {
			continue
		}
		seen[mem.key] = true
		a, ok := sc.accs[mem.key]
		if !ok {
			ra.evidence("member %s → %s: no per-IP finding", mem.cl, mem.sv)
			continue
		}
		for _, s := range a.sigs {
			ra.add(s)
		}
		ra.frames(a.f.Frames...)
		ra.evidence("member %s (per-IP score %.2f)", strings.TrimPrefix(a.f.Title, ""), a.score())
		if a.f.First != "" && (first == "" || a.f.First < first) {
			first = a.f.First
		}
		if a.f.Last > last {
			last = a.f.Last
		}
		for _, ev := range a.f.Evidence {
			if !strings.HasPrefix(ev, "member ") {
				ra.f.Evidence = append(ra.f.Evidence, "  "+ev)
			}
		}
		sc.drop(mem.key)
	}
	if first != "" {
		ra.f.First, ra.f.Last = first, last
	}
	ra.evidence("K1 roll-up: %d events from %d server IPs / %d ports under one name", nEvents, nServers, nPorts)
}
