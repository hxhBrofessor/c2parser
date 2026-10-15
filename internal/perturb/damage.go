package perturb

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/google/gopacket/layers"
)

func rng(seed uint64) *rand.Rand { return rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)) }

// Drop removes each packet with probability p.
func Drop(pkts []Packet, p float64, seed uint64) ([]Packet, Change) {
	r := rng(seed)
	out := make([]Packet, 0, len(pkts))
	for _, x := range pkts {
		if r.Float64() >= p {
			out = append(out, x)
		}
	}
	return out, Change{Transform: "drop", Params: map[string]any{"p": p, "seed": seed}, In: len(pkts), Out: len(out), Changed: len(pkts) - len(out)}
}

// Dup duplicates each packet with probability p (exact copy, same time).
func Dup(pkts []Packet, p float64, seed uint64) ([]Packet, Change) {
	r := rng(seed)
	out := make([]Packet, 0, len(pkts))
	n := 0
	for _, x := range pkts {
		out = append(out, x)
		if r.Float64() < p {
			y := x
			y.Data = append([]byte(nil), x.Data...)
			out = append(out, y)
			n++
		}
	}
	return out, Change{Transform: "dup", Params: map[string]any{"p": p, "seed": seed}, In: len(pkts), Out: len(out), Changed: n}
}

// Reorder swaps adjacent packets with probability p (timestamps travel
// with the packets, so file order and time order disagree).
func Reorder(pkts []Packet, p float64, seed uint64) ([]Packet, Change) {
	r := rng(seed)
	out := clone(pkts)
	n := 0
	for i := 0; i+1 < len(out); i++ {
		if r.Float64() < p {
			out[i], out[i+1] = out[i+1], out[i]
			n += 2
			i++
		}
	}
	return out, Change{Transform: "reorder", Params: map[string]any{"p": p, "seed": seed}, In: len(pkts), Out: len(out), Changed: n}
}

// Snap truncates stored packets to n bytes; orig_len keeps the wire length.
func Snap(pkts []Packet, n int) ([]Packet, Change) {
	out := clone(pkts)
	c := 0
	for i := range out {
		if n > 0 && len(out[i].Data) > n {
			out[i].Data = out[i].Data[:n]
			c++
		}
	}
	return out, Change{Transform: "snap", Params: map[string]any{"snaplen": n}, In: len(pkts), Out: len(out), Changed: c}
}

// Skip drops the first fraction of packets (capture started mid-session).
func Skip(pkts []Packet, frac float64) ([]Packet, Change) {
	k := int(float64(len(pkts)) * frac)
	k = max(0, min(k, len(pkts)))
	out := clone(pkts[k:])
	return out, Change{Transform: "skip", Params: map[string]any{"fraction": frac}, In: len(pkts), Out: len(out), Changed: k}
}

// Jitter adds U[−s, +s] seconds of timestamp noise (sensor clock,
// batching). File order is kept.
func Jitter(pkts []Packet, s float64, seed uint64) ([]Packet, Change) {
	r := rng(seed)
	out := clone(pkts)
	n := 0
	for i := range out {
		if s > 0 {
			out[i].Timestamp = out[i].Timestamp.Add(time.Duration((r.Float64()*2 - 1) * s * float64(time.Second)))
			n++
		}
	}
	return out, Change{Transform: "jitter", Params: map[string]any{"seconds": s, "seed": seed}, In: len(pkts), Out: len(out), Changed: n}
}

// Conflict inserts, for each TCP data segment with probability p, a
// retransmission covering the same sequence range with different bytes.
// before=true puts the conflicting copy first (1 µs earlier), so a
// first-wins reassembler keeps the wrong data.
func Conflict(pkts []Packet, p float64, before bool, seed uint64) ([]Packet, Change) {
	r := rng(seed)
	out := make([]Packet, 0, len(pkts))
	n := 0
	for _, x := range pkts {
		f, ok := parse(x)
		if !ok || f.proto != 6 || f.payload < 0 || f.plen == 0 || r.Float64() >= p {
			out = append(out, x)
			continue
		}
		y := x
		y.Data = append([]byte(nil), x.Data...)
		for i := f.payload; i < len(y.Data); i++ {
			y.Data[i] = byte(r.IntN(256))
		}
		fullTCPChecksum(&y, f)
		n++
		if before {
			y.Timestamp = x.Timestamp.Add(-time.Microsecond)
			out = append(out, y, x)
		} else {
			y.Timestamp = x.Timestamp.Add(time.Microsecond)
			out = append(out, x, y)
		}
	}
	return out, Change{Transform: "conflict", Params: map[string]any{"p": p, "before": before, "seed": seed}, In: len(pkts), Out: len(out), Changed: n}
}

// OneWay keeps only one direction of every flow: "c2s" keeps packets from
// the flow initiator (TCP SYN sender, else first sender), "s2c" the rest.
// Non-IPv4 packets are kept.
func OneWay(pkts []Packet, dir string) ([]Packet, Change, error) {
	if dir != "c2s" && dir != "s2c" {
		return nil, Change{}, fmt.Errorf("oneway: dir must be c2s or s2c")
	}
	init := map[flowKey][4]byte{}
	initPort := map[flowKey]uint16{}
	for _, x := range pkts { // SYN senders first
		f, ok := parse(x)
		if ok && f.l4 >= 0 && f.proto == 6 && f.flags&0x12 == 0x02 {
			if _, seen := init[f.key()]; !seen {
				init[f.key()], initPort[f.key()] = f.src, f.sport
			}
		}
	}
	out := make([]Packet, 0, len(pkts))
	for _, x := range pkts {
		f, ok := parse(x)
		if !ok || f.l4 < 0 {
			out = append(out, x)
			continue
		}
		k := f.key()
		if _, seen := init[k]; !seen {
			init[k], initPort[k] = f.src, f.sport
		}
		fromInit := f.src == init[k] && f.sport == initPort[k]
		if fromInit == (dir == "c2s") {
			out = append(out, x)
		}
	}
	return out, Change{Transform: "oneway", Params: map[string]any{"dir": dir}, In: len(pkts), Out: len(out), Changed: len(pkts) - len(out)}, nil
}

// Wrap encapsulates every Ethernet frame: "vlan" (802.1Q, VID 100),
// "qinq" (802.1ad 200 + 802.1Q 100), "gre" (transparent Ethernet
// bridging), "erspan" (GRE + ERSPAN type II) or "vxlan" (UDP 4789, VNI
// 4242). Tunnel outer headers run 10.255.0.1 → 10.255.0.2.
func Wrap(pkts []Packet, kind string) ([]Packet, Change, error) {
	out := make([]Packet, 0, len(pkts))
	var seq uint32
	for _, x := range pkts {
		if x.LinkType != layers.LinkTypeEthernet {
			return nil, Change{}, fmt.Errorf("wrap: needs Ethernet frames (got %v)", x.LinkType)
		}
		y := x
		var outer []byte
		switch kind {
		case "vlan", "qinq":
			if len(x.Data) < 14 {
				out = append(out, x)
				continue
			}
			tag := []byte{0x81, 0x00, 0x00, 100}
			if kind == "qinq" {
				tag = []byte{0x88, 0xa8, 0x00, 200, 0x81, 0x00, 0x00, 100}
			}
			d := append([]byte{}, x.Data[:12]...)
			d = append(d, tag...)
			d = append(d, x.Data[12:]...)
			y.Data, y.OrigLen = d, x.OrigLen+len(tag)
			out = append(out, y)
			continue
		case "gre":
			outer = greHdr(0x6558, nil)
		case "erspan":
			seq++
			er := make([]byte, 8)
			binary.BigEndian.PutUint16(er[0:], 1<<12) // version 1 (type II), VLAN 0
			binary.BigEndian.PutUint16(er[2:], 7)     // COS 0, En 0, T 0, session 7
			outer = greHdr(0x88be, &seq)
			outer = append(outer, er...)
		case "vxlan":
			u := make([]byte, 8)
			binary.BigEndian.PutUint16(u[0:], 49152+uint16(len(x.Data)%4096))
			binary.BigEndian.PutUint16(u[2:], 4789)
			vx := []byte{0x08, 0, 0, 0, 0, 0x10, 0x92, 0} // VNI 4242
			outer = append(u, vx...)
		default:
			return nil, Change{}, fmt.Errorf("wrap: unknown kind %q", kind)
		}
		proto := byte(47)
		if kind == "vxlan" {
			proto = 17
		}
		wire := len(outer) + x.OrigLen
		ip := ipv4Hdr(proto, 20+wire)
		if kind == "vxlan" {
			binary.BigEndian.PutUint16(outer[4:], uint16(8+8+x.OrigLen)) // UDP length; checksum 0
		}
		eth := []byte{0, 0x0a, 0, 0, 0, 1, 0, 0x0a, 0, 0, 0, 2, 0x08, 0x00}
		d := append(append(append(eth, ip...), outer...), x.Data...)
		y.Data, y.OrigLen = d, len(eth)+len(ip)+wire
		out = append(out, y)
	}
	return out, Change{Transform: "wrap", Params: map[string]any{"kind": kind}, In: len(pkts), Out: len(out), Changed: len(out)}, nil
}

func greHdr(proto uint16, seq *uint32) []byte {
	h := make([]byte, 4)
	binary.BigEndian.PutUint16(h[2:], proto)
	if seq != nil {
		h[0] = 0x10 // S bit
		h = binary.BigEndian.AppendUint32(h, *seq)
	}
	return h
}

func ipv4Hdr(proto byte, total int) []byte {
	h := []byte{0x45, 0, byte(total >> 8), byte(total), 0, 0, 0x40, 0, 64, proto, 0, 0, 10, 255, 0, 1, 10, 255, 0, 2}
	var s uint32
	for i := 0; i < 20; i += 2 {
		s += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	binary.BigEndian.PutUint16(h[10:], ^uint16(s))
	return h
}
