package synth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/google/gopacket"
)

func payloadLayer(b []byte) gopacket.SerializableLayer { return gopacket.Payload(b) }

// QUIC client Initial packets for fixtures (RFC 9000 / 9001 / 9369): a
// long header, CRYPTO frames carrying a ClientHello, AEAD protection with
// the Initial keys derived from the DCID, then header protection.

// QUIC versions.
const (
	QUICv1 uint32 = 0x00000001
	QUICv2 uint32 = 0x6b3343cf
)

func expandLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := binary.BigEndian.AppendUint16(nil, uint16(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), n)
	if err != nil {
		panic(err)
	}
	return out
}

// QUICClientKeys returns the client Initial key, iv and hp for a DCID.
func QUICClientKeys(version uint32, dcid []byte) (key, iv, hp []byte) {
	salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	prefix := "quic "
	if version == QUICv2 {
		salt = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
		prefix = "quicv2 "
	}
	initial, _ := hkdf.Extract(sha256.New, dcid, salt)
	secret := expandLabel(initial, "client in", 32)
	return expandLabel(secret, prefix+"key", 16), expandLabel(secret, prefix+"iv", 12), expandLabel(secret, prefix+"hp", 16)
}

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return binary.BigEndian.AppendUint16(b, uint16(v)|0x4000)
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(b, uint32(v)|0x80000000)
	}
	return binary.BigEndian.AppendUint64(b, v|0xc0<<56)
}

// CryptoFrame is one QUIC CRYPTO frame.
func CryptoFrame(offset uint64, data []byte) []byte {
	b := appendVarint([]byte{0x06}, offset)
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}

// QUICInitial protects payload (frames) as a client Initial with a 4-byte
// packet number, padding the payload to padTo bytes (≥ 1162 makes the
// datagram 1200+ bytes, as clients must).
func QUICInitial(version uint32, dcid, scid []byte, pn uint32, payload []byte, padTo int) []byte {
	for len(payload) < padTo {
		payload = append(payload, 0)
	}
	typ := byte(0xc0) // v1 Initial
	if version == QUICv2 {
		typ = 0xd0
	}
	h := []byte{typ | 0x03} // 4-byte packet number
	h = binary.BigEndian.AppendUint32(h, version)
	h = append(h, byte(len(dcid)))
	h = append(h, dcid...)
	h = append(h, byte(len(scid)))
	h = append(h, scid...)
	h = append(h, 0)                               // token length
	h = appendVarint(h, uint64(4+len(payload)+16)) // length: pn + payload + tag
	pnOff := len(h)
	h = binary.BigEndian.AppendUint32(h, pn)
	key, iv, hp := QUICClientKeys(version, dcid)
	blk, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(blk)
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 4; i++ {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}
	ct := aead.Seal(nil, nonce, payload, h)
	pkt := append(append([]byte(nil), h...), ct...)
	hpb, _ := aes.NewCipher(hp)
	mask := make([]byte, 16)
	hpb.Encrypt(mask, pkt[pnOff+4:pnOff+20])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < 4; i++ {
		pkt[pnOff+i] ^= mask[1+i]
	}
	return pkt
}

// ClientHelloMsg is the ClientHello handshake message (no TLS record
// header), as carried in QUIC CRYPTO frames.
func ClientHelloMsg(sni string, alpn []string) []byte { return ClientHello(sni, alpn)[5:] }

// QUICSession writes one QUIC connection's client Initial(s) carrying a
// ClientHello for sni, split over `split` packets with the CRYPTO frames
// in reverse order (chaos-protection-like), then short-header traffic.
func (b *Builder) QUICSession(ts time.Time, cli string, cport uint16, srv string, sport uint16, version uint32, dcid []byte, sni string, split, extra int) time.Time {
	ch := ClientHelloMsg(sni, []string{"h3"})
	if split < 1 {
		split = 1
	}
	chunk := (len(ch) + split - 1) / split
	for i := split - 1; i >= 0; i-- {
		lo, hi := i*chunk, min((i+1)*chunk, len(ch))
		pkt := QUICInitial(version, dcid, []byte{1, 2, 3, 4}, uint32(split-1-i), CryptoFrame(uint64(lo), ch[lo:hi]), 1162)
		_ = b.UDP(ts, cli, cport, srv, sport, payloadLayer(pkt))
		ts = ts.Add(time.Millisecond)
	}
	for i := 0; i < extra; i++ {
		short := append([]byte{0x40}, make([]byte, 40)...)
		_ = b.UDP(ts.Add(20*time.Millisecond), srv, sport, cli, cport, payloadLayer(short))
		_ = b.UDP(ts.Add(25*time.Millisecond), cli, cport, srv, sport, payloadLayer(short))
		ts = ts.Add(30 * time.Millisecond)
	}
	return ts
}
