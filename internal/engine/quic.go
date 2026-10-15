package engine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
)

// QUIC Initial decryption (v10a 2.3; RFC 9000, RFC 9001 §5, RFC 9369).
// Initial packets are protected with keys derived from the client's
// Destination Connection ID and a public salt, so a passive observer can
// recover the ClientHello: SNI, ALPN and JA4 (prefix "q", from the
// transport). The certificate (Handshake level) and HTTP/3 bodies
// (1-RTT) are not recoverable. Behaviour follows quic-go (MIT) only.

const (
	quicV1 uint32 = 0x00000001
	quicV2 uint32 = 0x6b3343cf
)

var (
	quicSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicSaltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

// quicKeys is one direction's Initial packet protection.
type quicKeys struct {
	secret, key, iv, hp []byte
	aead                cipher.AEAD
	hpBlock             cipher.Block
}

// hkdfExpandLabel is TLS 1.3's HKDF-Expand-Label with an empty context.
func hkdfExpandLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), n)
	if err != nil {
		panic(err) // n ≤ 255·32, never fails
	}
	return out
}

// quicInitialKeys derives the client or server Initial keys for a version
// and DCID.
func quicInitialKeys(version uint32, dcid []byte, client bool) (*quicKeys, error) {
	salt, prefix := quicSaltV1, "quic "
	switch version {
	case quicV1:
	case quicV2:
		salt, prefix = quicSaltV2, "quicv2 "
	default:
		return nil, errors.New("unsupported QUIC version")
	}
	initial, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return nil, err
	}
	label := "server in"
	if client {
		label = "client in"
	}
	k := &quicKeys{secret: hkdfExpandLabel(initial, label, 32)}
	k.key = hkdfExpandLabel(k.secret, prefix+"key", 16)
	k.iv = hkdfExpandLabel(k.secret, prefix+"iv", 12)
	k.hp = hkdfExpandLabel(k.secret, prefix+"hp", 16)
	blk, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, err
	}
	if k.aead, err = cipher.NewGCM(blk); err != nil {
		return nil, err
	}
	if k.hpBlock, err = aes.NewCipher(k.hp); err != nil {
		return nil, err
	}
	return k, nil
}

// hpMask is the 5-byte header-protection mask for a 16-byte sample.
func (k *quicKeys) hpMask(sample []byte) []byte {
	m := make([]byte, 16)
	k.hpBlock.Encrypt(m, sample)
	return m[:5]
}

func quicVarint(b []byte) (v uint64, n int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	n = 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, false
	}
	v = uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n, true
}

// quicLong is a parsed long-header packet (before unprotection).
type quicLong struct {
	version  uint32
	initial  bool
	dcid     []byte
	pnOffset int // offset of the protected packet number
	end      int // offset just past this packet (coalescing)
}

// parseQUICLong parses one long-header packet at the start of b.
func parseQUICLong(b []byte) (p quicLong, ok bool) {
	if len(b) < 7 || b[0]&0x80 == 0 {
		return p, false
	}
	p.version = binary.BigEndian.Uint32(b[1:])
	typ := (b[0] >> 4) & 3
	switch p.version {
	case quicV1:
		p.initial = typ == 0
	case quicV2:
		p.initial = typ == 1
	default:
		return p, false
	}
	i := 5
	dl := int(b[i])
	i++
	if dl > 20 || i+dl >= len(b) {
		return p, false
	}
	p.dcid = b[i : i+dl]
	i += dl
	sl := int(b[i])
	i++
	if sl > 20 || i+sl > len(b) {
		return p, false
	}
	i += sl
	if p.initial {
		tl, n, ok := quicVarint(b[i:])
		if !ok || uint64(len(b)-i-n) < tl {
			return p, false
		}
		i += n + int(tl)
	} else if (b[0]>>4)&3 == quicRetryType(p.version) {
		p.end = len(b) // Retry has no Length field
		return p, true
	}
	length, n, ok := quicVarint(b[i:])
	if !ok {
		return p, false
	}
	i += n
	p.pnOffset = i
	if length > uint64(len(b)-i) {
		p.end = len(b) // truncated (snaplen) or bogus: stop here
	} else {
		p.end = i + int(length)
	}
	return p, true
}

func quicRetryType(v uint32) byte {
	if v == quicV2 {
		return 0
	}
	return 3
}

var errQUICShort = errors.New("quic: packet too short to sample")

// unprotect removes header protection and decrypts an Initial packet in
// pkt (one coalesced packet, pkt[:p.end]). It returns the plaintext payload.
func (k *quicKeys) unprotect(pkt []byte, p quicLong) ([]byte, error) {
	if p.end > len(pkt) || p.pnOffset+4+16 > p.end {
		return nil, errQUICShort
	}
	hdr := make([]byte, p.pnOffset+4)
	copy(hdr, pkt[:p.pnOffset+4])
	mask := k.hpMask(pkt[p.pnOffset+4 : p.pnOffset+20])
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&3) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[p.pnOffset+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[p.pnOffset+i])
	}
	aad := hdr[:p.pnOffset+pnLen]
	nonce := make([]byte, 12)
	copy(nonce, k.iv)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}
	ct := pkt[p.pnOffset+pnLen : p.end]
	return k.aead.Open(nil, nonce, ct, aad)
}

// cryptoFrames extracts CRYPTO frame data (offset → bytes) from an Initial
// payload. Initial packets may also carry PADDING, PING, ACK and
// CONNECTION_CLOSE.
func cryptoFrames(pl []byte) (frames map[uint64][]byte, ok bool) {
	frames = map[uint64][]byte{}
	for i := 0; i < len(pl); {
		ft, n, ok := quicVarint(pl[i:])
		if !ok {
			return frames, false
		}
		i += n
		switch {
		case ft == 0x00 || ft == 0x01: // PADDING, PING
		case ft == 0x02 || ft == 0x03: // ACK
			var v uint64
			fields := 4 // largest, delay, range count, first range
			for f := 0; f < fields; f++ {
				x, n, ok := quicVarint(pl[i:])
				if !ok {
					return frames, false
				}
				if f == 2 {
					v = x
				}
				i += n
			}
			if v > 256 {
				return frames, false
			}
			for r := uint64(0); r < 2*v; r++ { // gap, range
				_, n, ok := quicVarint(pl[i:])
				if !ok {
					return frames, false
				}
				i += n
			}
			if ft == 0x03 {
				for f := 0; f < 3; f++ { // ECN counts
					_, n, ok := quicVarint(pl[i:])
					if !ok {
						return frames, false
					}
					i += n
				}
			}
		case ft == 0x06: // CRYPTO
			off, n, ok := quicVarint(pl[i:])
			if !ok {
				return frames, false
			}
			i += n
			l, n, ok := quicVarint(pl[i:])
			if !ok || l > uint64(len(pl)-i-n) {
				return frames, false
			}
			i += n
			if off < 1<<20 {
				frames[off] = pl[i : i+int(l)]
			}
			i += int(l)
		case ft == 0x1c || ft == 0x1d: // CONNECTION_CLOSE: nothing more of interest
			return frames, true
		default:
			return frames, false
		}
	}
	return frames, true
}

// cryptoStream reassembles CRYPTO data by offset (duplicates and overlaps
// merge; Chromium shuffles and splits CRYPTO frames across Initials).
type cryptoStream struct {
	parts map[uint64][]byte
	size  int
}

func (c *cryptoStream) add(off uint64, b []byte) {
	if c.parts == nil {
		c.parts = map[uint64][]byte{}
	}
	if old, ok := c.parts[off]; ok && len(old) >= len(b) {
		return
	}
	if c.size+len(b) > 1<<16 {
		return
	}
	c.parts[off] = append([]byte(nil), b...)
	c.size += len(b)
}

// prefix returns the contiguous bytes from offset 0.
func (c *cryptoStream) prefix() []byte {
	offs := make([]uint64, 0, len(c.parts))
	for o := range c.parts {
		offs = append(offs, o)
	}
	sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })
	var out []byte
	for _, o := range offs {
		if o > uint64(len(out)) {
			break
		}
		b := c.parts[o]
		if end := o + uint64(len(b)); end > uint64(len(out)) {
			out = append(out, b[uint64(len(out))-o:]...)
		}
	}
	return out
}

// clientHello returns the ClientHello body once it is complete.
func (c *cryptoStream) clientHello() ([]byte, bool) {
	p := c.prefix()
	if len(p) < 4 || p[0] != 1 {
		return nil, false
	}
	l := int(p[1])<<16 | int(p[2])<<8 | int(p[3])
	if len(p) < 4+l {
		return nil, false
	}
	return p[4 : 4+l], true
}

// quicFlow is per-UDP-flow Initial state.
type quicFlow struct {
	keys    *quicKeys // from the first client Initial's DCID (kept after the DCID changes)
	version uint32
	crypto  cryptoStream
	done    bool
	tries   int
}

// quicMaxInitials bounds the client Initials examined per flow.
const quicMaxInitials = 16

// onQUICClient handles one client→server datagram on a QUIC flow.
func (e *Engine) onQUICClient(u *udpFlow, d []byte) {
	q := u.q
	if q == nil {
		q = &quicFlow{}
		u.q = q
	}
	if q.done || q.tries >= quicMaxInitials {
		return
	}
	for off := 0; off < len(d); {
		p, ok := parseQUICLong(d[off:])
		if !ok || p.end <= 0 {
			return
		}
		pkt := d[off : off+p.end]
		off += p.end
		if !p.initial {
			continue
		}
		q.tries++
		// Keys come from this packet's DCID; after the server's first
		// Initial the client switches DCID but keeps the original keys.
		k, err := quicInitialKeys(p.version, p.dcid, true)
		if err != nil {
			return
		}
		pl, err := k.unprotect(pkt, p)
		switch {
		case err != nil && q.keys != nil && q.version == p.version:
			pl, err = q.keys.unprotect(pkt, p)
		case err == nil && q.keys == nil:
			q.keys, q.version = k, p.version
		}
		if err != nil {
			e.counters.QUICInitialErrors++
			continue
		}
		frames, _ := cryptoFrames(pl)
		for o, b := range frames {
			q.crypto.add(o, b)
		}
		if body, ok := q.crypto.clientHello(); ok {
			q.done = true
			if hello, ok := parseClientHello(body); ok {
				e.onQUICHello(u, &hello)
			}
			q.crypto = cryptoStream{}
			return
		}
	}
}

// onQUICHello records a recovered ClientHello on the flow's channel, like a
// TLS one (SNI joins the K1 name keys and the fleet/poller cadence index).
func (e *Engine) onQUICHello(u *udpFlow, h *tlsHello) {
	a := u.ch.tlsAgg()
	a.conns++
	if h.sni == "" {
		a.noSNI++
	} else {
		a.sni.inc(h.sni)
		e.addName(u.server.Addr(), h.sni)
	}
	ja3, _ := h.ja3()
	a.ja3.inc(ja3)
	a.ja4.inc(h.ja4(true))
	for _, p := range h.alpn {
		a.alpn.inc(p)
	}
	for _, x := range h.exts {
		if x == 0xfe0d {
			u.ch.quicECH++
		}
	}
	u.ch.quicHellos++
	e.counters.QUICClientHellos++
}
