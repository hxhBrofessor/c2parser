package synth

import (
	"encoding/binary"
	"net/netip"
	"strings"
)

// DCE/RPC connection-oriented PDUs for fixtures (C706 ch. 12; MS-RPCE).

// UUIDBytes encodes a UUID string in DCE (little-endian fields) order.
func UUIDBytes(u string) []byte {
	h := strings.ReplaceAll(u, "-", "")
	raw := make([]byte, 16)
	for i := 0; i < 16 && 2*i+1 < len(h); i++ {
		var v byte
		for _, c := range h[2*i : 2*i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			case c >= 'a' && c <= 'f':
				v |= byte(c-'a') + 10
			case c >= 'A' && c <= 'F':
				v |= byte(c-'A') + 10
			}
		}
		raw[i] = v
	}
	out := make([]byte, 16)
	out[0], out[1], out[2], out[3] = raw[3], raw[2], raw[1], raw[0]
	out[4], out[5] = raw[5], raw[4]
	out[6], out[7] = raw[7], raw[6]
	copy(out[8:], raw[8:])
	return out
}

const ndr = "8a885d04-1ceb-11c9-9fe8-08002b104860"

// DCEPDU frames a PDU; level > 0 appends a sec_trailer and a 16-byte
// auth value (5 = integrity, 6 = privacy).
func DCEPDU(typ, flags byte, callID uint32, body []byte, level uint8) []byte {
	var auth []byte
	if level > 0 {
		pad := (4 - (16+len(body))%4) % 4
		body = append(body, make([]byte, pad)...)
		auth = append([]byte{9, level, byte(pad), 0, 0, 0, 0, 0}, make([]byte, 16)...)
	}
	h := []byte{5, 0, typ, flags, 0x10, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(h[8:], uint16(16+len(body)+len(auth)))
	if level > 0 {
		binary.LittleEndian.PutUint16(h[10:], 16)
	}
	h = binary.LittleEndian.AppendUint32(h, callID)
	return append(append(h, body...), auth...)
}

// DCEBind binds one presentation context (id 0) to iface.
func DCEBind(callID uint32, iface string) []byte {
	b := []byte{0xb8, 0x10, 0xb8, 0x10, 0, 0, 0, 0, 1, 0, 0, 0}
	b = append(b, 0, 0, 1, 0)
	b = append(b, UUIDBytes(iface)...)
	b = append(b, 1, 0, 0, 0)
	b = append(b, UUIDBytes(ndr)...)
	b = append(b, 2, 0, 0, 0)
	return DCEPDU(11, 0x03, callID, b, 0)
}

// DCEBindAck accepts one context.
func DCEBindAck(callID uint32, port string) []byte {
	b := []byte{0xb8, 0x10, 0xb8, 0x10, 1, 0, 0, 0}
	sec := []byte(port + "\x00")
	b = binary.LittleEndian.AppendUint16(b, uint16(len(sec)))
	b = append(b, sec...)
	for (16+len(b))%4 != 0 {
		b = append(b, 0)
	}
	b = append(b, 1, 0, 0, 0, 0, 0, 0, 0)
	b = append(b, UUIDBytes(ndr)...)
	return DCEPDU(12, 0x03, callID, append(b, 2, 0, 0, 0), 0)
}

// DCERequest is a single-fragment request on context 0.
func DCERequest(callID uint32, opnum uint16, stub []byte, level uint8) []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(len(stub)))
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, opnum)
	return DCEPDU(0, 0x03, callID, append(b, stub...), level)
}

// DCEResponse is a single-fragment response.
func DCEResponse(callID uint32, stub []byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(len(stub)))
	b = append(b, 0, 0, 0, 0)
	return DCEPDU(2, 0x03, callID, append(b, stub...), 0)
}

// EPMTower is an ncacn_ip_tcp tower for iface at ip:port.
func EPMTower(iface, ip string, port uint16) []byte {
	floor := func(lhs, rhs []byte) []byte {
		b := binary.LittleEndian.AppendUint16(nil, uint16(len(lhs)))
		b = append(b, lhs...)
		b = binary.LittleEndian.AppendUint16(b, uint16(len(rhs)))
		return append(b, rhs...)
	}
	t := binary.LittleEndian.AppendUint16(nil, 5)
	t = append(t, floor(append(append([]byte{0x0d}, UUIDBytes(iface)...), 4, 0), []byte{0, 0})...)
	t = append(t, floor(append(append([]byte{0x0d}, UUIDBytes(ndr)...), 2, 0), []byte{0, 0})...)
	t = append(t, floor([]byte{0x0b}, []byte{0, 0})...)
	t = append(t, floor([]byte{0x07}, []byte{byte(port >> 8), byte(port)})...)
	a := netip.MustParseAddr(ip).As4()
	return append(t, floor([]byte{0x09}, a[:])...)
}

// EPTMapResponse is an ept_map response stub carrying one tower.
func EPTMapResponse(tower []byte) []byte {
	s := make([]byte, 20)
	s = binary.LittleEndian.AppendUint32(s, 1)
	s = binary.LittleEndian.AppendUint32(s, 4)
	s = binary.LittleEndian.AppendUint32(s, 0)
	s = binary.LittleEndian.AppendUint32(s, 1)
	s = binary.LittleEndian.AppendUint32(s, 0x20000)
	s = binary.LittleEndian.AppendUint32(s, uint32(len(tower)))
	s = binary.LittleEndian.AppendUint32(s, uint32(len(tower)))
	s = append(s, tower...)
	for len(s)%4 != 0 {
		s = append(s, 0)
	}
	return binary.LittleEndian.AppendUint32(s, 0)
}

// Interface UUIDs used by the presets.
const (
	IfaceEPM     = "e1af8308-5d1f-11c9-91a4-08002b14a0fa"
	IfaceWbem    = "9556dc99-828c-11cf-a37e-00aa003240c7"
	IfaceDRSUAPI = "e3514235-4b06-11d1-ab04-00c04fc2dcd2"
	IfaceSAMR    = "12345778-1234-abcd-ef00-0123456789ac"
)
