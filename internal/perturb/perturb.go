// Package perturb rewrites real captures for stress testing (v9 rev 2
// Phase 1.2): damage, encapsulation, re-addressing and cloning, re-timing
// of one channel's transactions, and splicing.
//
// Every transform is deterministic for a given seed, keeps payload bytes
// unless its purpose is to change them, fixes IPv4/TCP/UDP checksums
// incrementally (RFC 1624, so truncated packets stay consistent), and
// returns a Change row describing exactly what it did.
//
// Captures derived from lab pcaps stay outside the repo, like the
// originals; tests build them at run time from C2PARSER_TESTDATA.
package perturb

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/google/gopacket/layers"

	"c2parser/internal/pcapio"
)

// Packet is one frame. OrigLen is the wire length (≥ len(Data)).
type Packet = pcapio.Packet

// Change is the manifest row a transform emits.
type Change struct {
	Transform string         `json:"transform"`
	Params    map[string]any `json:"params,omitempty"`
	In        int            `json:"packets_in"`
	Out       int            `json:"packets_out"`
	Changed   int            `json:"packets_changed"`
	Detail    string         `json:"detail,omitempty"`
}

// Read loads a pcap or pcapng into memory (data copied).
func Read(path string) ([]Packet, error) {
	r, err := pcapio.Open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var out []Packet
	for {
		p, err := r.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		p.Data = append([]byte(nil), p.Data...)
		if p.OrigLen < len(p.Data) {
			p.OrigLen = len(p.Data)
		}
		out = append(out, p)
	}
}

// Write saves packets as a classic nanosecond pcap with the first
// packet's link type (true orig_len kept).
func Write(path string, pkts []Packet) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	bw := bufio.NewWriter(f)
	if err := WriteTo(bw, pkts); err != nil {
		f.Close()
		return err
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// WriteTo writes packets to w as a classic pcap.
func WriteTo(w io.Writer, pkts []Packet) error {
	link := layers.LinkTypeEthernet
	if len(pkts) > 0 {
		link = pkts[0].LinkType
	}
	pw, err := pcapio.NewWriter(w, link)
	if err != nil {
		return err
	}
	for _, p := range pkts {
		if p.LinkType != link {
			return fmt.Errorf("mixed link types %v and %v", link, p.LinkType)
		}
		if err := pw.WritePacketOrig(p.Timestamp, p.Data, p.OrigLen); err != nil {
			return err
		}
	}
	return nil
}

// clone deep-copies packets.
func clone(pkts []Packet) []Packet {
	out := make([]Packet, len(pkts))
	for i, p := range pkts {
		p.Data = append([]byte(nil), p.Data...)
		out[i] = p
	}
	return out
}

// SortByTime orders packets by timestamp (stable).
func SortByTime(pkts []Packet) {
	sort.SliceStable(pkts, func(i, j int) bool { return pkts[i].Timestamp.Before(pkts[j].Timestamp) })
}

// ---------------------------------------------------------------- parsing

// frame locates the IPv4 header and transport header in an Ethernet (or
// raw IPv4) frame, through any number of 802.1Q / 802.1ad tags.
type frame struct {
	ip, l4  int // offsets; -1 when absent
	proto   byte
	frag    bool
	src     [4]byte
	dst     [4]byte
	sport   uint16
	dport   uint16
	payload int // transport payload offset (TCP/UDP), -1 if absent
	plen    int // transport payload length on the wire (from IP total length)
	flags   byte
	seq     uint32
}

func parse(p Packet) (f frame, ok bool) {
	f.ip, f.l4, f.payload = -1, -1, -1
	d := p.Data
	off := 0
	switch p.LinkType {
	case layers.LinkTypeEthernet:
		if len(d) < 14 {
			return f, false
		}
		et := binary.BigEndian.Uint16(d[12:])
		off = 14
		for et == 0x8100 || et == 0x88a8 {
			if len(d) < off+4 {
				return f, false
			}
			et = binary.BigEndian.Uint16(d[off+2:])
			off += 4
		}
		if et != 0x0800 {
			return f, false
		}
	case layers.LinkTypeRaw, layers.LinkTypeIPv4:
	default:
		return f, false
	}
	if len(d) < off+20 || d[off]>>4 != 4 {
		return f, false
	}
	f.ip = off
	ihl := int(d[off]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(d[off+2:]))
	f.proto = d[off+9]
	fl := binary.BigEndian.Uint16(d[off+6:])
	f.frag = fl&0x2000 != 0 || fl&0x1fff != 0
	copy(f.src[:], d[off+12:off+16])
	copy(f.dst[:], d[off+16:off+20])
	if f.frag || (f.proto != 6 && f.proto != 17) {
		return f, true
	}
	l4 := off + ihl
	if len(d) < l4+8 {
		return f, true
	}
	f.l4 = l4
	f.sport = binary.BigEndian.Uint16(d[l4:])
	f.dport = binary.BigEndian.Uint16(d[l4+2:])
	switch f.proto {
	case 6:
		if len(d) < l4+20 {
			f.l4 = -1
			return f, true
		}
		hl := int(d[l4+12]>>4) * 4
		f.flags = d[l4+13]
		f.seq = binary.BigEndian.Uint32(d[l4+4:])
		f.payload = l4 + hl
		f.plen = total - ihl - hl
	case 17:
		f.payload = l4 + 8
		f.plen = total - ihl - 8
	}
	if f.plen < 0 {
		f.plen = 0
	}
	return f, true
}

// flowKey is a direction-independent 5-tuple.
type flowKey struct {
	a, b   [4]byte
	pa, pb uint16
	proto  byte
}

func (f frame) key() flowKey {
	k := flowKey{a: f.src, b: f.dst, pa: f.sport, pb: f.dport, proto: f.proto}
	if string(k.a[:]) > string(k.b[:]) || (k.a == k.b && k.pa > k.pb) {
		k.a, k.b, k.pa, k.pb = k.b, k.a, k.pb, k.pa
	}
	return k
}

// ---------------------------------------------------------------- checksums

// csumAdjust updates a ones'-complement checksum for a change of old to
// new (equal, even lengths), per RFC 1624 eqn. 3.
func csumAdjust(sum uint16, old, new []byte) uint16 {
	s := uint32(^sum)
	for i := 0; i+1 < len(old); i += 2 {
		s += uint32(^binary.BigEndian.Uint16(old[i:]))
		s += uint32(binary.BigEndian.Uint16(new[i:]))
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

// patch overwrites b[at:at+len(new)] and fixes the IPv4 header checksum
// (when inIP) and the TCP/UDP checksum (when inL4 or inIP, as the
// pseudo-header covers addresses), as far as the captured bytes allow.
func patch(p *Packet, f frame, at int, new []byte, inIP, inL4 bool) {
	d := p.Data
	if at+len(new) > len(d) {
		return
	}
	old := append([]byte(nil), d[at:at+len(new)]...)
	copy(d[at:], new)
	if inIP && f.ip >= 0 && len(d) >= f.ip+12 {
		c := binary.BigEndian.Uint16(d[f.ip+10:])
		binary.BigEndian.PutUint16(d[f.ip+10:], csumAdjust(c, old, new))
	}
	if (inIP || inL4) && f.l4 >= 0 {
		var co int
		switch f.proto {
		case 6:
			co = f.l4 + 16
		case 17:
			co = f.l4 + 6
		default:
			return
		}
		if len(d) < co+2 {
			return
		}
		c := binary.BigEndian.Uint16(d[co:])
		if f.proto == 17 && c == 0 {
			return // UDP checksum not in use
		}
		nc := csumAdjust(c, old, new)
		if f.proto == 17 && nc == 0 {
			nc = 0xffff
		}
		binary.BigEndian.PutUint16(d[co:], nc)
	}
}

// fullTCPChecksum recomputes the TCP checksum of an untruncated packet.
func fullTCPChecksum(p *Packet, f frame) {
	d := p.Data
	if f.proto != 6 || f.l4 < 0 || p.OrigLen != len(d) {
		return
	}
	ihl := int(d[f.ip]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(d[f.ip+2:]))
	if f.ip+total > len(d) || f.l4+20 > f.ip+total {
		return // inconsistent lengths: leave the checksum alone
	}
	seg := d[f.l4 : f.ip+total]
	binary.BigEndian.PutUint16(d[f.l4+16:], 0)
	var s uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			s += uint32(binary.BigEndian.Uint16(b[i:]))
		}
		if len(b)%2 == 1 {
			s += uint32(b[len(b)-1]) << 8
		}
	}
	add(d[f.ip+12 : f.ip+20])
	s += 6 + uint32(total-ihl)
	add(seg)
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	binary.BigEndian.PutUint16(d[f.l4+16:], ^uint16(s))
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
