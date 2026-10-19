package engine

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// HTTP CONNECT tunnels (v9c 2.3). After a 2xx answer to CONNECT
// host:port the connection carries another protocol end to end. When that
// is TLS, the inner ClientHello / ServerHello / certificate are parsed
// (SNI, JA3/JA4, cert signals land on the proxy channel) and the client's
// bursts form a timing series keyed by (client, CONNECT target) — the K1
// name — so a beacon through a proxy is scored like one to the target.
// Non-TLS tunnel payloads fall back to opaque bytes, as before.

// connectTLS enables inner-TLS parsing of CONNECT tunnels (a var so tests
// can compare with v9b behaviour).
var connectTLS = true

type tunnelAgg struct {
	client     netip.Addr
	target     string // host:port from CONNECT
	proxy      netip.AddrPort
	t, s       []float64
	conns      int
	sni, ja4   map[string]int
	first      time.Time
	last       time.Time
	firstFrame int64
}

func (e *Engine) tunnelOf(c *tcpConn) *tunnelAgg {
	k := c.client.Addr().String() + "|" + strings.ToLower(c.tunnelTarget) + "|" + c.server.String()
	if e.tunnels == nil {
		e.tunnels = map[string]*tunnelAgg{}
	}
	t := e.tunnels[k]
	if t == nil {
		t = &tunnelAgg{client: c.client.Addr(), target: c.tunnelTarget, proxy: c.server, sni: map[string]int{}, ja4: map[string]int{},
			first: c.start, firstFrame: c.firstFrame}
		e.tunnels[k] = t
		e.tunOrder = append(e.tunOrder, t)
	}
	return t
}

// openTunnel marks the connection as a CONNECT tunnel and arms inner TLS
// parsing.
func (e *Engine) openTunnel(c *tcpConn) {
	if !connectTLS || c.connectTarget == "" || c.tunnelTarget != "" {
		return
	}
	c.tunnelTarget = c.connectTarget
	c.tunTLS = [2]*tlsHalf{{e: e, c: c, client: true}, {e: e, c: c}}
	t := e.tunnelOf(c)
	t.conns++
	if c.last.After(t.last) {
		t.last = c.last
	}
}

// tunnelData feeds tunnel bytes to the inner TLS parser. A half that sees
// no TLS handshake gives up (tlsHalf.finish) and the bytes stay opaque.
func (e *Engine) tunnelData(c *tcpConn, client bool, data []byte, ts time.Time, frame int64) {
	if c.tunTLS[0] == nil || len(data) == 0 {
		return
	}
	i := 1
	if client {
		i = 0
	}
	if h := c.tunTLS[i]; !h.done {
		if !client || len(h.buf) > 0 || (len(data) > 0 && data[0] == 0x16) {
			h.feed(data, ts, frame)
		} else {
			h.finish() // client spoke first and it isn't a TLS handshake record
		}
	}
	if t := e.tunnelOf(c); ts.After(t.last) {
		t.last = ts
	}
}

// connBurst records one client→server burst on the connection's channel
// and, for a CONNECT tunnel, on the tunnel's (client, target) series.
func (e *Engine) connBurst(c *tcpConn, start time.Time, n int64) {
	c.ch.addBurst(e, start, n)
	if c.tunnelTarget != "" {
		t := e.tunnelOf(c)
		if e.room(len(t.t)) {
			t.t = append(t.t, e.rel(start))
			t.s = append(t.s, float64(n))
		}
	}
}

// scoreTunnels scores each (client, CONNECT target) series. Scope rules use
// the target, not the proxy: a beacon to an outside name through an
// internal proxy is still outbound.
func (e *Engine) scoreTunnels(sc *scorer) {
	for _, t := range e.tunOrder {
		host, port, err := net.SplitHostPort(t.target)
		if err != nil {
			host, port = t.target, "443"
		}
		if a, err := netip.ParseAddr(host); err == nil && e.isInternal(a) && e.isInternal(t.client) {
			continue // internal → internal through a proxy: not egress
		}
		if len(t.ja4) == 0 {
			continue // no inner ClientHello: opaque tunnel, as before
		}
		key := "K1|" + t.client.String() + "|" + strings.ToLower(host)
		bsigs, strength := e.beacon("connect_tunnel", key, ModelPerRequest, t.t, t.s, e.cfg.Beacon, 0.65, "tunnel client bursts")
		if strength < 0.55 {
			continue
		}
		title := fmt.Sprintf("Beaconing %s → %s:%s via proxy %s (HTTP CONNECT)", t.client, host, port, t.proxy)
		a := sc.get("tun|"+t.client.String()+"|"+strings.ToLower(host), CatC2, title, t.client, netip.Addr{}, t.first, t.last)
		a.f.Server = host
		for _, s := range bsigs {
			a.add(s)
		}
		a.evidence("%d tunnel connection(s) through %s; CONNECT %s", t.conns, t.proxy, t.target)
		if len(t.sni) > 0 {
			a.evidence("inner TLS SNI: %s; JA4: %s", fmtCounts(t.sni, 3), fmtCounts(t.ja4, 2))
		} else {
			a.evidence("inner TLS without SNI; JA4: %s", fmtCounts(t.ja4, 2))
		}
		a.frames(t.firstFrame)
	}
}
