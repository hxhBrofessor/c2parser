package synth

import (
	"encoding/base32"
	"fmt"
	"math/rand/v2"
	"strings"
)

// Generic DNS wire experiments. These deliberately invented envelopes and
// alphabet sweeps are NOT Sliver protocol fixtures. Kept as a separate control
// for the positional profiler; see SliverDNSFixture below for the bounded,
// independently serialized snapshot-derived query shapes. No network I/O.

// DNSAlphaRFC4648 and DNSAlphaCustom32 are the two alphabets the
// study is run under.
const (
	DNSAlphaRFC4648  = "abcdefghijklmnopqrstuvwxyz234567"
	DNSAlphaCustom32 = "ab1c2d3e4f5g6h7j8k9m0npqrtuvwxyz"
)

// DNSWireModel parameterises the modelled wire shape.
type DNSWireModel struct {
	Alphabet string // 32 symbols
	Envelope string // "protobuf" | "fixed"
	LabelLen int    // label length (≤ 63)
}

// Base32 encodes b MSB-first over the model's alphabet, without padding.
func (m DNSWireModel) Base32(b []byte) string {
	var sb strings.Builder
	acc, bits := uint(0), uint(0)
	for _, c := range b {
		acc = acc<<8 | uint(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			sb.WriteByte(m.Alphabet[acc>>bits&31])
		}
	}
	if bits > 0 {
		sb.WriteByte(m.Alphabet[acc<<(5-bits)&31])
	}
	return sb.String()
}

func pbVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// envelope serialises one fragment.
func (m DNSWireModel) envelope(session, msgType, nonce uint32, start, total int, data []byte) []byte {
	if m.Envelope == "fixed" {
		b := []byte{byte(session >> 24), byte(session >> 16), byte(session >> 8), byte(session),
			byte(msgType), byte(start), byte(total),
			byte(nonce >> 24), byte(nonce >> 16), byte(nonce >> 8), byte(nonce)}
		return append(b, data...)
	}
	b := make([]byte, 0, 24+len(data))
	b = pbVarint(append(b, 0x08), uint64(session)) // invented generic field 1: session
	b = pbVarint(append(b, 0x10), uint64(msgType)) // invented generic field 2: type
	b = pbVarint(append(b, 0x18), uint64(nonce))   // 3: random nonce
	b = pbVarint(append(b, 0x20), uint64(start))   // 4: fragment start
	b = pbVarint(append(b, 0x28), uint64(total))   // 5: total length
	b = pbVarint(append(b, 0x32), uint64(len(data)))
	return append(b, data...) // 6: data
}

// Message builds the query names for one modelled message: the
// ciphertext is split into fragments sized to the name capacity, each
// fragment is its own envelope (fresh nonce), base32-encoded and split
// into LabelLen-char labels under zone.
func (m DNSWireModel) Message(r *rand.Rand, zone string, session, msgType uint32, ciphertext []byte) []string {
	ll := m.LabelLen
	if ll <= 0 || ll > 63 {
		ll = 60
	}
	room := 253 - len(zone) - 1
	perName := max(16, (room/(ll+1))*ll*5/8-24) // encoded chars → bytes, minus envelope
	var names []string
	for off := 0; off < len(ciphertext) || off == 0; off += perName {
		end := min(off+perName, len(ciphertext))
		enc := m.Base32(m.envelope(session, msgType, r.Uint32(), off, len(ciphertext), ciphertext[off:end]))
		var labels []string
		for len(enc) > 0 {
			n := min(ll, len(enc))
			labels = append(labels, enc[:n])
			enc = enc[n:]
		}
		names = append(names, strings.Join(labels, ".")+"."+zone)
		if end == len(ciphertext) {
			break
		}
	}
	return names
}

// SliverDNSFixture is a local test input, not a transport or session client.
// Schema: supplied protobuf/dnspb/dns.proto:5-29. Zero proto3 values are omitted.
// Snapshot Git identity is unverified. No upstream code or generated protobuf
// is imported; ascending field order is a fixture convention.
type SliverDNSFixture struct {
	Type, ID, Start, Stop, Size uint32
	Data                        []byte
}

const (
	SliverDNSNOP         uint32 = 0
	SliverDNSInit        uint32 = 2
	SliverDNSPoll        uint32 = 3
	SliverDNSClose       uint32 = 4
	SliverDNSManifest    uint32 = 6
	SliverDNSToImplant   uint32 = 7
	SliverDNSFromImplant uint32 = 8
	SliverDNSClear       uint32 = 9
	MaxDNSFixtureData           = 4096
)

func (m SliverDNSFixture) Marshal() ([]byte, error) {
	switch m.Type {
	case SliverDNSNOP, SliverDNSInit, SliverDNSPoll, SliverDNSClose, SliverDNSManifest, SliverDNSToImplant, SliverDNSFromImplant, SliverDNSClear:
	default:
		return nil, fmt.Errorf("unsupported DNS fixture type %d", m.Type)
	}
	if len(m.Data) > MaxDNSFixtureData {
		return nil, fmt.Errorf("DNS fixture payload exceeds %d", MaxDNSFixtureData)
	}
	b := make([]byte, 0, 32+len(m.Data))
	for i, v := range []uint32{m.Type, m.ID, m.Start, m.Stop, m.Size} {
		if v != 0 {
			b = pbVarint(append(b, byte((i+1)<<3)), uint64(v))
		}
	}
	if len(m.Data) > 0 {
		b = pbVarint(append(b, 0x32), uint64(len(m.Data)))
		b = append(b, m.Data...)
	}
	return b, nil
}

// SliverDNSID combines the 8-bit message and nonzero 24-bit session parts.
// The observed nextMsgID counter uses modulo 255, so 255 is not generated.
func SliverDNSID(session uint32, message uint8) (uint32, error) {
	if session == 0 || session > 0xffffff || message == 255 {
		return 0, fmt.Errorf("invalid DNS fixture session/message ID")
	}
	return uint32(message)<<24 | session, nil
}

// SliverDNSPollFixture places an eight-byte nonce in Data; no nonce field
// exists in the schema (dnsclient.go:915-924). Randomness is supplied locally.
func SliverDNSPollFixture(session uint32, nonce [8]byte) (SliverDNSFixture, error) {
	id, err := SliverDNSID(session, 0)
	return SliverDNSFixture{Type: SliverDNSPoll, ID: id, Data: nonce[:]}, err
}

func dnsFixtureParent(zone string) (string, int, error) {
	zone = strings.TrimSuffix(strings.TrimPrefix(zone, "."), ".")
	if len(zone) == 0 || len(zone) > 120 {
		return "", 0, fmt.Errorf("DNS fixture zone length out of bounds")
	}
	for _, label := range strings.Split(zone, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", 0, fmt.Errorf("invalid DNS fixture zone label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", 0, fmt.Errorf("invalid DNS fixture zone symbol")
			}
		}
	}
	parent := "." + zone + "."
	// Source name budget, including inserted label dots and trailing root dot.
	space := 254 - len(parent) - (1 + (254-len(parent))/64)
	return parent, space, nil
}

// SliverDNSName uses the supplied custom unpadded base32 alphabet and
// 63-symbol labels. The returned absolute name includes the final root dot.
func SliverDNSName(zone string, m SliverDNSFixture) (string, error) {
	parent, space, err := dnsFixtureParent(zone)
	if err != nil {
		return "", err
	}
	b, err := m.Marshal()
	if err != nil {
		return "", err
	}
	enc := base32.NewEncoding(DNSAlphaCustom32).WithPadding(base32.NoPadding).EncodeToString(b)
	if len(enc) > space {
		return "", fmt.Errorf("DNS fixture exceeds name capacity")
	}
	labels := make([]string, 0, 4)
	for len(enc) > 0 {
		n := min(63, len(enc))
		labels = append(labels, enc[:n])
		enc = enc[n:]
	}
	if len(labels) == 0 {
		return "", fmt.Errorf("empty DNS fixture")
	}
	name := strings.Join(labels, ".") + parent
	if len(name) > 254 {
		return "", fmt.Errorf("DNS fixture exceeds absolute-name limit")
	}
	return name, nil
}

// SliverDNSFragments models DATA_FROM_IMPLANT: a shared ID and Size,
// per-fragment Start and Data; Stop remains omitted (unlike read requests).
// Bounded maximal-fitting packing is OUR modeling choice, not a copy of the
// source's iterative packer or a promise of identical fragment boundaries.
func SliverDNSFragments(zone string, session uint32, message uint8, data []byte) ([]SliverDNSFixture, error) {
	if len(data) == 0 || len(data) > MaxDNSFixtureData {
		return nil, fmt.Errorf("DNS fixture data length out of bounds")
	}
	if _, _, err := dnsFixtureParent(zone); err != nil {
		return nil, err
	}
	id, err := SliverDNSID(session, message)
	if err != nil {
		return nil, err
	}
	out := make([]SliverDNSFixture, 0, 32)
	for start := 0; start < len(data); {
		lo, hi, best := 1, min(256, len(data)-start), 0
		for lo <= hi {
			n := (lo + hi) / 2
			m := SliverDNSFixture{Type: SliverDNSFromImplant, ID: id, Start: uint32(start), Size: uint32(len(data)), Data: data[start : start+n]}
			if _, err := SliverDNSName(zone, m); err == nil {
				best = n
				lo = n + 1
			} else {
				hi = n - 1
			}
		}
		if best == 0 || len(out) >= 128 {
			return nil, fmt.Errorf("DNS fixture fragment budget exhausted")
		}
		m := SliverDNSFixture{Type: SliverDNSFromImplant, ID: id, Start: uint32(start), Size: uint32(len(data)), Data: append([]byte(nil), data[start:start+best]...)}
		out = append(out, m)
		start += best
	}
	return out, nil
}
