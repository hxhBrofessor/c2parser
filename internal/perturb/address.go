package perturb

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

// AddrMap is a consistent rewrite: IPv4 → IPv4, and optionally ports
// (applied to any TCP/UDP port equal to the key, either direction).
type AddrMap struct {
	IP   map[netip.Addr]netip.Addr
	Port map[uint16]uint16
}

// Readdress applies m to every IPv4 packet, fixing checksums. Payloads
// are untouched (addresses inside DNS answers or HTTP Host headers stay).
func Readdress(pkts []Packet, m AddrMap) ([]Packet, Change, error) {
	for a, b := range m.IP {
		if !a.Is4() || !b.Is4() {
			return nil, Change{}, fmt.Errorf("readdress: IPv4 only (%v → %v)", a, b)
		}
	}
	out := clone(pkts)
	n := 0
	for i := range out {
		if rewrite(&out[i], m) {
			n++
		}
	}
	return out, Change{Transform: "readdress", Params: map[string]any{"ips": len(m.IP), "ports": len(m.Port)}, In: len(pkts), Out: len(out), Changed: n}, nil
}

// rewrite applies m to one packet in place.
func rewrite(p *Packet, m AddrMap) bool {
	f, ok := parse(*p)
	if !ok || f.ip < 0 {
		return false
	}
	changed := false
	for _, at := range []int{f.ip + 12, f.ip + 16} {
		a := netip.AddrFrom4([4]byte(p.Data[at : at+4]))
		if b, ok := m.IP[a]; ok && b != a {
			nb := b.As4()
			patch(p, f, at, nb[:], true, false)
			changed = true
		}
	}
	if f.l4 >= 0 && len(m.Port) > 0 {
		for _, at := range []int{f.l4, f.l4 + 2} {
			v := binary.BigEndian.Uint16(p.Data[at:])
			if w, ok := m.Port[v]; ok && w != v {
				patch(p, f, at, binary.BigEndian.AppendUint16(nil, w), false, true)
				changed = true
			}
		}
	}
	return changed
}

// Clone copies every packet involving client onto each address in to,
// shifted by k·offset for the k-th clone (k from 1): N independent
// clients with the same traffic (fleet fixtures). The original stays.
func Clone(pkts []Packet, client netip.Addr, to []netip.Addr, offset time.Duration) ([]Packet, Change, error) {
	out := clone(pkts)
	n := 0
	for k, a := range to {
		m := AddrMap{IP: map[netip.Addr]netip.Addr{client: a}}
		for _, x := range pkts {
			f, ok := parse(x)
			if !ok || f.ip < 0 || (netip.AddrFrom4(f.src) != client && netip.AddrFrom4(f.dst) != client) {
				continue
			}
			y := x
			y.Data = append([]byte(nil), x.Data...)
			rewrite(&y, m)
			y.Timestamp = x.Timestamp.Add(time.Duration(k+1) * offset)
			out = append(out, y)
			n++
		}
	}
	SortByTime(out)
	return out, Change{Transform: "clone", Params: map[string]any{"client": client.String(), "to": len(to), "offset_ms": ms(offset)}, In: len(pkts), Out: len(out), Changed: n}, nil
}

// Redirect spreads the flows to server over the addresses in to
// (round-robin by flow start, or random with seed): k redirectors in
// front of one name.
func Redirect(pkts []Packet, server netip.Addr, to []netip.Addr, mode string, seed uint64) ([]Packet, Change, error) {
	if len(to) == 0 {
		return nil, Change{}, fmt.Errorf("redirect: no addresses")
	}
	r := rng(seed)
	assign := map[flowKey]netip.Addr{}
	out := clone(pkts)
	n := 0
	for i := range out {
		f, ok := parse(out[i])
		if !ok || f.l4 < 0 || (netip.AddrFrom4(f.src) != server && netip.AddrFrom4(f.dst) != server) {
			continue
		}
		k := f.key()
		a, seen := assign[k]
		if !seen {
			if mode == "random" {
				a = to[r.IntN(len(to))]
			} else {
				a = to[len(assign)%len(to)]
			}
			assign[k] = a
		}
		rewrite(&out[i], AddrMap{IP: map[netip.Addr]netip.Addr{server: a}})
		n++
	}
	return out, Change{Transform: "redirect", Params: map[string]any{"server": server.String(), "to": len(to), "mode": mode, "flows": len(assign)}, In: len(pkts), Out: len(out), Changed: n}, nil
}

// Splice merges add into base, shifting add so its first packet lands at
// base's first timestamp + offset. Both must share a link type.
func Splice(base, add []Packet, offset time.Duration) ([]Packet, Change, error) {
	if len(base) == 0 || len(add) == 0 {
		return append(clone(base), clone(add)...), Change{Transform: "splice"}, nil
	}
	if base[0].LinkType != add[0].LinkType {
		return nil, Change{}, fmt.Errorf("splice: link types differ (%v, %v)", base[0].LinkType, add[0].LinkType)
	}
	first := add[0].Timestamp
	for _, p := range add {
		if p.Timestamp.Before(first) {
			first = p.Timestamp
		}
	}
	b0 := base[0].Timestamp
	for _, p := range base {
		if p.Timestamp.Before(b0) {
			b0 = p.Timestamp
		}
	}
	shift := b0.Add(offset).Sub(first)
	out := clone(base)
	for _, p := range clone(add) {
		p.Timestamp = p.Timestamp.Add(shift)
		out = append(out, p)
	}
	SortByTime(out)
	return out, Change{Transform: "splice", Params: map[string]any{"offset_s": offset.Seconds(), "added": len(add)}, In: len(base), Out: len(out), Changed: len(add)}, nil
}
