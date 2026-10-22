package engine

import (
	"fmt"
	"math"
	"net/netip"
	"strings"

	"c2parser/internal/stats"
)

// Cadence index for the timing-only cap (v9 rev 2 Phase 0.1, v9c D2/D3).
// Built for both engines from the same event series the scorers use:
// destination (HTTP Host / TLS SNI name, else server IP; DNS base domain)
// → client → period and scheduler shape. Benign reasons:
//
//   - fleet: ≥ max(3, 25 % of active internal clients) reach one
//     destination on the same cadence (fleet schedulers hit many hosts; an
//     implant usually lands on a few);
//   - poller: one internal client reaches ≥ 3 internal servers on the same
//     cadence (monitoring scrapes, backup and inventory agents);
//   - scheduler shape on the series itself (GPO, Jamf, WSUS, chrony,
//     anchored grid, MDM ladder, browser updater, WireGuard keep-alive off
//     UDP 53).
//
// A cross-run prevalence store would refine this later.

type cadenceEntry struct {
	period    float64
	scheduler string // scheduler-shape annotation, "" if none
}

type cadence struct {
	dests    map[string]map[string]cadenceEntry // dest → client → entry
	internal map[string]map[string]cadenceEntry // internal client → internal server IP → entry
	active   int                                // internal clients with ≥ 1 outbound flow
}

// Fleet threshold: max(fleetMinClients, ⌈fleetFrac × active internal
// clients⌉). Vars so the mutation tests can move them.
var (
	fleetMinClients  = 3
	fleetFrac        = 0.25
	pollerMinTargets = 3
	gapShapes        = true
)

func (c *cadence) add(dest, client string, times []float64, shape string, internalPair bool) {
	if dest == "" || len(times) < 4 {
		return
	}
	t := stats.AnalyzeTiming(times, stats.TimingParams{})
	if t.PeriodSec <= 0 {
		return
	}
	sh := shape
	if sh == "" {
		sh = stats.SchedulerShape(t)
	}
	if sh == "" && t.Anchored {
		sh = "anchored scheduler (ρ₁ ≈ −0.5)"
	}
	if sh == "" && gapShapes {
		sh = stats.GapShape(times)
	}
	put := func(m map[string]map[string]cadenceEntry, a, b string) {
		x := m[a]
		if x == nil {
			x = map[string]cadenceEntry{}
			m[a] = x
		}
		if old, ok := x[b]; !ok || old.scheduler == "" {
			x[b] = cadenceEntry{t.PeriodSec, sh}
		}
	}
	put(c.dests, dest, client)
	if internalPair && isIP(dest) {
		put(c.internal, client, dest)
	}
}

func isIP(s string) bool { _, err := netip.ParseAddr(strings.Trim(s, "[]")); return err == nil }

func (e *Engine) cadenceIndex() *cadence {
	c := &cadence{dests: map[string]map[string]cadenceEntry{}, internal: map[string]map[string]cadenceEntry{}}
	act := map[netip.Addr]bool{}
	for _, ch := range e.chOrder {
		if e.isInternal(ch.key.client) {
			act[ch.key.client] = true
		}
	}
	c.active = len(act)
	in := func(cl, srv netip.Addr) bool { return e.isInternal(cl) && e.isInternal(srv) }
	// Name keys (Host / SNI) use the K1 series: every server IP behind
	// the name merged, so redirectors don't split one cadence (v9c 2.1).
	type nk struct{ name, client string }
	named := map[nk][]float64{}
	var nkOrder []nk
	addNamed := func(name, cl string, t []float64) {
		k := nk{strings.ToLower(name), cl}
		if have, ok := named[k]; ok {
			named[k] = append(have, t...) // capped below: append copies
			return
		}
		nkOrder = append(nkOrder, k)
		named[k] = t[:len(t):len(t)] // share until a second series arrives
	}
	for _, h := range e.httpOrder {
		host := strings.Split(h.key.host, ":")[0]
		cl := h.key.client.String()
		ip := in(h.key.client, h.key.server)
		c.add(h.key.server.String(), cl, h.reqT, "", ip)
		if host != "" && !isIP(host) {
			addNamed(host, cl, h.reqT)
		}
	}
	for _, ch := range e.chOrder {
		cl := ch.key.client.String()
		shape := ""
		// WireGuard keep-alives explain timing only off UDP 53 (v9c D2c).
		if wireguardShape(ch) && (!wgPortAware || ch.key.port != 53) {
			shape = "WireGuard keep-alive (32 B, ~25 s)"
		}
		c.add(ch.key.server.String(), cl, ch.burstT, shape, in(ch.key.client, ch.key.server))
		if ch.tls != nil && ch.tls.sni.len() > 0 {
			sni, _ := topCount(ch.tls.sni.Map())
			if shape != "" {
				c.add(strings.ToLower(sni), cl, ch.burstT, shape, false)
			} else {
				addNamed(sni, cl, ch.burstT)
			}
		}
	}
	for _, k := range nkOrder {
		c.add(k.name, k.client, stats.Sorted(named[k]), "", false)
	}
	for _, domainKey := range sortedDNSDomainKeys(e.dns.domains) {
		d := e.dns.domains[domainKey]
		for _, cl := range sortedDNSClientAddrs(d.clients) {
			s := d.clients[cl]
			c.add(d.base, cl.String(), s.t, "", false)
		}
	}
	return c
}

func sortedDNSDomainKeys(domains map[string]*dnsDomain) []string {
	keys := make([]string, 0, len(domains))
	for k := range domains {
		keys = append(keys, k)
	}
	return keys
}

func sortedDNSClientAddrs(clients map[netip.Addr]*dnsSeries) []netip.Addr {
	keys := make([]netip.Addr, 0, len(clients))
	for k := range clients {
		keys = append(keys, k)
	}
	return keys
}

// fleetNeed is the client count the fleet reason needs.
func (c *cadence) fleetNeed() int {
	return max(fleetMinClients, int(math.Ceil(fleetFrac*float64(c.active))))
}

func samePeriod(a, b float64) bool { return math.Abs(a-b) <= 0.2*b }

// benignReason explains why a timing-only finding looks like a benign
// scheduler ("" if it doesn't).
func (c *cadence) benignReason(f *Finding) string {
	dests := append([]string{f.Server}, f.ServerNames...)
	shape := ""
	for _, d := range dests {
		m := c.dests[strings.ToLower(d)]
		self, ok := m[f.Client]
		if !ok {
			continue
		}
		n := 0
		for _, e := range m {
			if samePeriod(e.period, self.period) {
				n++
			}
		}
		if n >= c.fleetNeed() {
			return fmt.Sprintf("fleet-wide periodic destination (%d of %d hosts)", n, max(c.active, n))
		}
		if shape == "" && self.scheduler != "" {
			shape = "cadence matches " + self.scheduler
		}
	}
	if shape != "" {
		return shape
	}
	if srv := c.internal[f.Client]; srv != nil {
		if self, ok := srv[f.Server]; ok {
			n := 0
			for _, e := range srv {
				if samePeriod(e.period, self.period) {
					n++
				}
			}
			if n >= pollerMinTargets {
				return fmt.Sprintf("internal poller (%d targets)", n)
			}
		}
	}
	return ""
}
