package engine

import (
	"encoding/binary"
	"sort"

	"c2parser/internal/stats"
)

// looksDNS is a cheap structural check for a DNS message: a 12-byte header
// with a standard opcode, 1–4 questions and a plausible first label.
func looksDNS(p []byte) bool {
	if len(p) < 12 {
		return false
	}
	if op := p[2] >> 3 & 0x0f; op > 6 {
		return false
	}
	qd := binary.BigEndian.Uint16(p[4:])
	if qd == 0 || qd > 4 {
		return false
	}
	if len(p) > 12 && p[12] > 63 {
		return false
	}
	return true
}

// wgPortAware is the port test of the WireGuard rule (a var so the
// mutation test can remove it).
var wgPortAware = true

// wireguardShape: a UDP channel that is mostly 32-byte payloads in both
// directions (a WireGuard keep-alive is a 32-byte transport message with an
// empty payload) at a ~25 s cadence (keep-alives are sent only after
// 25 s without traffic, so real use breaks the series up).
func wireguardShape(ch *channel) bool {
	if ch.key.proto != "udp" || ch.pktsOut < 10 || float64(ch.udp32Out) < 0.8*float64(ch.pktsOut) {
		return false
	}
	if ch.pktsIn > 0 && float64(ch.udp32In) < 0.8*float64(ch.pktsIn) {
		return false
	}
	if len(ch.burstT) < 6 {
		return false
	}
	t := stats.Sorted(ch.burstT) // bursts from several flows arrive out of order
	g := make([]float64, 0, len(t)-1)
	for i := 1; i < len(t); i++ {
		g = append(g, t[i]-t[i-1])
	}
	sort.Float64s(g)
	m := g[len(g)/2]
	return m >= 20 && m <= 30
}

// wireguardOnDNSPort: the WireGuard shape on UDP 53 with payloads that are
// not DNS. Sliver's WireGuard transport defaults to UDP 53 (indicators doc
// §2), so here the shape raises suspicion instead of explaining it away.
func wireguardOnDNSPort(ch *channel) bool {
	return wgPortAware && ch.key.port == 53 && wireguardShape(ch) && float64(ch.udpNonDNS) >= 0.8*float64(ch.pktsOut)
}
