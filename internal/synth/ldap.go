package synth

import (
	"encoding/binary"
	"strconv"
)

// LDAP (RFC 4511) messages for fixtures: SearchRequest with a filter
// tree, attributes and controls; SearchResultEntry / Done; SASL wrapping
// as NTLM-signed or Kerberos GSS wrap tokens (sealed or not).

// BER encodes one TLV.
func BER(tag byte, val []byte) []byte {
	n := len(val)
	switch {
	case n < 0x80:
		return append([]byte{tag, byte(n)}, val...)
	case n < 0x100:
		return append([]byte{tag, 0x81, byte(n)}, val...)
	case n < 0x10000:
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, val...)
	}
	return append([]byte{tag, 0x84, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, val...)
}

func berInt(v int) []byte {
	if v >= 0 && v < 0x80 {
		return []byte{byte(v)}
	}
	var b []byte
	for x := v; x > 0; x >>= 8 {
		b = append([]byte{byte(x)}, b...)
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return b
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// LDAP filter builders (RFC 4511 §4.5.1).
func FAnd(fs ...[]byte) []byte { return BER(0xa0, cat(fs...)) }
func FOr(fs ...[]byte) []byte  { return BER(0xa1, cat(fs...)) }
func FNot(f []byte) []byte     { return BER(0xa2, f) }
func FEq(attr, val string) []byte {
	return BER(0xa3, cat(BER(0x04, []byte(attr)), BER(0x04, []byte(val))))
}
func FPresent(attr string) []byte { return BER(0x87, []byte(attr)) }
func FSub(attr, initial string) []byte {
	return BER(0xa4, cat(BER(0x04, []byte(attr)), BER(0x30, BER(0x80, []byte(initial)))))
}
func FBitAnd(attr string, v int) []byte { // attr:1.2.840.113556.1.4.803:=v
	return BER(0xa9, cat(BER(0x81, []byte("1.2.840.113556.1.4.803")), BER(0x82, []byte(attr)), BER(0x83, []byte(strconv.Itoa(v)))))
}

// LDAPControl builds a Control; value may be nil.
func LDAPControl(oid string, value []byte) []byte {
	b := BER(0x04, []byte(oid))
	if value != nil {
		b = append(b, BER(0x04, value)...)
	}
	return BER(0x30, b)
}

// PagedControl is the simple paged results control (size, cookie).
func PagedControl(size int, cookie []byte) []byte {
	return LDAPControl("1.2.840.113556.1.4.319", BER(0x30, cat(BER(0x02, berInt(size)), BER(0x04, cookie))))
}

// SDFlagsControl asks for the DACL (SD_FLAGS 0x04).
func SDFlagsControl() []byte {
	return LDAPControl("1.2.840.113556.1.4.801", BER(0x30, BER(0x02, []byte{4})))
}

// LDAPSearch is a SearchRequest message (scope 0 base, 1 one, 2 subtree).
func LDAPSearch(msgID int, base string, scope int, filter []byte, attrs []string, controls ...[]byte) []byte {
	var al []byte
	for _, a := range attrs {
		al = append(al, BER(0x04, []byte(a))...)
	}
	req := cat(BER(0x04, []byte(base)), BER(0x0a, []byte{byte(scope)}), BER(0x0a, []byte{0}),
		BER(0x02, []byte{0}), BER(0x02, []byte{0}), BER(0x01, []byte{0}), filter, BER(0x30, al))
	msg := cat(BER(0x02, berInt(msgID)), BER(0x63, req))
	if len(controls) > 0 {
		msg = append(msg, BER(0xa0, cat(controls...))...)
	}
	return BER(0x30, msg)
}

// LDAPEntry is a SearchResultEntry with no attributes.
func LDAPEntry(msgID int, dn string) []byte {
	return BER(0x30, cat(BER(0x02, berInt(msgID)), BER(0x64, cat(BER(0x04, []byte(dn)), BER(0x30, nil)))))
}

// LDAPDone is a successful SearchResultDone.
func LDAPDone(msgID int) []byte {
	return BER(0x30, cat(BER(0x02, berInt(msgID)), BER(0x65, cat(BER(0x0a, []byte{0}), BER(0x04, nil), BER(0x04, nil)))))
}

// LDAPDoneCode is a SearchResultDone with resultCode code (4 =
// sizeLimitExceeded).
func LDAPDoneCode(msgID, code int) []byte {
	return BER(0x30, cat(BER(0x02, berInt(msgID)), BER(0x65, cat(BER(0x0a, []byte{byte(code)}), BER(0x04, nil), BER(0x04, nil)))))
}

// LDAPBind is a simple-less SASL BindRequest placeholder (GSS-SPNEGO).
func LDAPBind(msgID int) []byte {
	sasl := BER(0xa3, cat(BER(0x04, []byte("GSS-SPNEGO")), BER(0x04, []byte{0x60, 0x00})))
	return BER(0x30, cat(BER(0x02, berInt(msgID)), BER(0x60, cat(BER(0x02, []byte{3}), BER(0x04, nil), sasl))))
}

// SASLNTLM wraps msg as an NTLM-signed SASL buffer (signature, then data).
func SASLNTLM(msg []byte, seq uint32) []byte {
	sig := binary.LittleEndian.AppendUint32(nil, 1)
	sig = append(sig, 1, 2, 3, 4, 5, 6, 7, 8)
	sig = binary.LittleEndian.AppendUint32(sig, seq)
	p := append(sig, msg...)
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(p))), p...)
}

// SASLKrb wraps msg as a Kerberos GSS wrap token (RFC 4121) with RRC = 0;
// sealed replaces the data with opaque bytes, as encryption would.
func SASLKrb(msg []byte, sealed bool) []byte {
	flags := byte(0x01)
	if sealed {
		flags |= 0x02
	}
	return SASLKrbWrap(msg, flags, 0)
}

// SASLKrbWrap is a wrap token with the given flags (0x01 SentByAcceptor,
// 0x02 Sealed, 0x04 AcceptorSubkey) and right-rotation count. Windows
// sends RRC = EC = 12: the trailing 12-byte checksum rotated to the front
// of the payload (RFC 4121 §4.2.5). rrc may exceed the payload length
// (the rotation is then modulo the length).
func SASLKrbWrap(msg []byte, flags byte, rrc int) []byte {
	const ec = 12
	rrc &= 0xffff // a 16-bit field on the wire
	h := []byte{0x05, 0x04, flags, 0xff, 0, ec, byte(rrc >> 8), byte(rrc), 0, 0, 0, 0, 0, 0, 0, 1}
	data := msg
	if flags&0x02 != 0 {
		data = make([]byte, len(msg))
		for i := range data {
			data[i] = byte(0x9d ^ i)
		}
	}
	pl := append(append([]byte(nil), data...), make([]byte, ec)...) // data || checksum
	for i := len(data); i < len(pl); i++ {
		pl[i] = byte(0xc0 + i%16) // checksum bytes (never 0x30-led after rotation by chance: 0xc0..0xcf)
	}
	if n := len(pl); rrc > 0 && n > 0 {
		r := rrc % n
		pl = append(append([]byte(nil), pl[n-r:]...), pl[:n-r]...) // rotate right by r
	}
	p := append(h, pl...)
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(p))), p...)
}
