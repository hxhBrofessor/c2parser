package engine

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// TLS metadata without decryption: ClientHello → SNI, ALPN, JA3, JA4;
// ServerHello → JA3S, negotiated version; Certificate (TLS ≤ 1.2 only, it is
// encrypted in 1.3) → subject/issuer/validity/self-signed. This is the
// "infrastructure evidence" layer: when content is encrypted, fingerprints
// and certificates are what tie a channel to a C2 framework.

const (
	tlsMaxClientBuf = 64 << 10
	tlsMaxServerBuf = 256 << 10
)

type tlsHello struct {
	legacyVersion uint16
	ciphers       []uint16
	exts          []uint16
	groups        []uint16
	pointFmts     []uint8
	sigAlgs       []uint16
	alpn          []string
	sni           string
	versions      []uint16
}

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

func noGREASE(v []uint16) []uint16 {
	out := make([]uint16, 0, len(v))
	for _, x := range v {
		if !isGREASE(x) {
			out = append(out, x)
		}
	}
	return out
}

// tlsRecords concatenates handshake-record payloads from a TLS byte stream.
// done=true once a non-handshake record (CCS, alert, app data) is reached.
func tlsHandshakeBytes(b []byte) (hs []byte, done bool) {
	for len(b) >= 5 {
		typ := b[0]
		l := int(binary.BigEndian.Uint16(b[3:]))
		if len(b) < 5+l {
			return hs, false
		}
		if typ != 22 {
			return hs, true
		}
		hs = append(hs, b[5:5+l]...)
		b = b[5+l:]
	}
	return hs, false
}

func parseClientHello(m []byte) (h tlsHello, ok bool) {
	// m is the ClientHello body (after the 4-byte handshake header)
	r := reader{b: m}
	h.legacyVersion = r.u16()
	r.skip(32)
	r.skip(int(r.u8()))
	cl := int(r.u16())
	cs := r.take(cl)
	for i := 0; i+1 < len(cs); i += 2 {
		h.ciphers = append(h.ciphers, binary.BigEndian.Uint16(cs[i:]))
	}
	r.skip(int(r.u8()))
	if r.bad {
		return h, false
	}
	if r.left() < 2 {
		return h, true // no extensions
	}
	ext := reader{b: r.take(int(r.u16()))}
	for ext.left() >= 4 && !ext.bad {
		typ := ext.u16()
		d := reader{b: ext.take(int(ext.u16()))}
		h.exts = append(h.exts, typ)
		switch typ {
		case 0: // server_name
			list := reader{b: d.take(int(d.u16()))}
			for list.left() >= 3 && !list.bad {
				nt := list.u8()
				name := list.take(int(list.u16()))
				if nt == 0 && h.sni == "" {
					h.sni = string(name)
				}
			}
		case 10: // supported_groups
			g := d.take(int(d.u16()))
			for i := 0; i+1 < len(g); i += 2 {
				h.groups = append(h.groups, binary.BigEndian.Uint16(g[i:]))
			}
		case 11: // ec_point_formats
			h.pointFmts = append(h.pointFmts, d.take(int(d.u8()))...)
		case 13: // signature_algorithms
			sa := d.take(int(d.u16()))
			for i := 0; i+1 < len(sa); i += 2 {
				h.sigAlgs = append(h.sigAlgs, binary.BigEndian.Uint16(sa[i:]))
			}
		case 16: // ALPN
			list := reader{b: d.take(int(d.u16()))}
			for list.left() >= 1 && !list.bad {
				p := list.take(int(list.u8()))
				if !list.bad {
					h.alpn = append(h.alpn, string(p))
				}
			}
		case 43: // supported_versions
			v := d.take(int(d.u8()))
			for i := 0; i+1 < len(v); i += 2 {
				h.versions = append(h.versions, binary.BigEndian.Uint16(v[i:]))
			}
		}
	}
	return h, !ext.bad
}

func joinU16(v []uint16) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = strconv.Itoa(int(x))
	}
	return strings.Join(s, "-")
}

// JA3 = md5("SSLVersion,Ciphers,Extensions,EllipticCurves,PointFormats"),
// GREASE removed.
func (h tlsHello) ja3() (string, string) {
	pf := make([]string, len(h.pointFmts))
	for i, p := range h.pointFmts {
		pf[i] = strconv.Itoa(int(p))
	}
	full := fmt.Sprintf("%d,%s,%s,%s,%s", h.legacyVersion, joinU16(noGREASE(h.ciphers)), joinU16(noGREASE(h.exts)),
		joinU16(noGREASE(h.groups)), strings.Join(pf, "-"))
	sum := md5.Sum([]byte(full))
	return hex.EncodeToString(sum[:]), full
}

func tlsVerCode(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	}
	return "00"
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func sha12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func hex4list(v []uint16, sorted bool) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = fmt.Sprintf("%04x", x)
	}
	if sorted {
		sort.Strings(s)
	}
	return strings.Join(s, ",")
}

// ja4 implements the FoxIO JA4 TLS-client fingerprint
// (a_b_c: proto+version+sni+counts+alpn _ sha256(sorted ciphers)[:12] _
// sha256(sorted exts minus SNI/ALPN + "_" + sigalgs)[:12]).
func (h tlsHello) ja4(quic bool) string {
	proto := "t"
	if quic {
		proto = "q"
	}
	ver := h.legacyVersion
	if vs := noGREASE(h.versions); len(vs) > 0 {
		ver = 0
		for _, v := range vs {
			if v > ver {
				ver = v
			}
		}
	}
	sni := "i"
	if h.sni != "" {
		sni = "d"
	}
	ciphers := noGREASE(h.ciphers)
	exts := noGREASE(h.exts)
	alpn := "00"
	if len(h.alpn) > 0 && h.alpn[0] != "" {
		a := h.alpn[0]
		f, l := a[0], a[len(a)-1]
		if isAlnum(f) && isAlnum(l) {
			alpn = string([]byte{f, l})
		} else {
			hx := hex.EncodeToString([]byte(a))
			alpn = string([]byte{hx[0], hx[len(hx)-1]})
		}
	}
	a := fmt.Sprintf("%s%s%s%02d%02d%s", proto, tlsVerCode(ver), sni, min(len(ciphers), 99), min(len(exts), 99), alpn)
	b := sha12(hex4list(ciphers, true))
	var ce []uint16
	for _, x := range exts {
		if x != 0x0000 && x != 0x0010 {
			ce = append(ce, x)
		}
	}
	cIn := hex4list(ce, true)
	if len(h.sigAlgs) > 0 {
		cIn += "_" + hex4list(h.sigAlgs, false)
	}
	c := "000000000000"
	if len(ce) > 0 {
		c = sha12(cIn)
	}
	return a + "_" + b + "_" + c
}

// ServerHello → JA3S = md5("SSLVersion,Cipher,Extensions") and whether
// TLS 1.3 was negotiated (which hides the certificate).
func parseServerHello(m []byte) (ja3s string, tls13 bool, ok bool) {
	r := reader{b: m}
	ver := r.u16()
	r.skip(32)
	r.skip(int(r.u8()))
	cipher := r.u16()
	r.skip(1)
	if r.bad {
		return "", false, false
	}
	var exts []uint16
	if r.left() >= 2 {
		er := reader{b: r.take(int(r.u16()))}
		for er.left() >= 4 && !er.bad {
			t := er.u16()
			d := er.take(int(er.u16()))
			exts = append(exts, t)
			if t == 43 && len(d) == 2 && binary.BigEndian.Uint16(d) == 0x0304 {
				tls13 = true
			}
		}
	}
	sum := md5.Sum([]byte(fmt.Sprintf("%d,%d,%s", ver, cipher, joinU16(exts))))
	return hex.EncodeToString(sum[:]), tls13, true
}

// certInfo is what we keep from the leaf certificate.
type certInfo struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	SelfSigned bool      `json:"self_signed"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	DNSNames   []string  `json:"dns_names,omitempty"`
	Serial     string    `json:"serial"`
	SHA256     string    `json:"sha256"`
	cert       *x509.Certificate
}

func parseCertificateMsg(m []byte) *certInfo {
	r := reader{b: m}
	list := reader{b: r.take(int(r.u24()))}
	der := list.take(int(list.u24()))
	if r.bad || list.bad || len(der) == 0 {
		return nil
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(der)
	ci := &certInfo{Subject: c.Subject.String(), Issuer: c.Issuer.String(), NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		DNSNames: c.DNSNames, Serial: c.SerialNumber.String(), SHA256: hex.EncodeToString(sum[:]), cert: c}
	// Verify the signature with the cert's own key directly: CheckSignatureFrom
	// also enforces CA basic constraints, so it rejects ordinary self-signed
	// leaf certs (CA:FALSE or no basicConstraints) — most C2 server certs.
	ci.SelfSigned = string(c.RawSubject) == string(c.RawIssuer) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
	return ci
}

// ------------------------------------------------------------ stream halves

type tlsInfo struct {
	hello    *tlsHello
	ja3      string
	ja3full  string
	ja4      string
	ja3s     string
	tls13    bool
	cert     *certInfo
	clientOK bool
}

type tlsHalf struct {
	e      *Engine
	c      *tcpConn
	client bool
	buf    []byte
	done   bool
}

func (h *tlsHalf) gap()            { h.done = true; h.buf = nil }
func (h *tlsHalf) close(time.Time) {}

func (h *tlsHalf) feed(data []byte, _ time.Time, _ int64) {
	if h.done {
		return
	}
	h.buf = append(h.buf, data...)
	limit := tlsMaxServerBuf
	if h.client {
		limit = tlsMaxClientBuf
	}
	hs, end := tlsHandshakeBytes(h.buf)
	if h.c.tls == nil {
		h.c.tls = &tlsInfo{}
	}
	ti := h.c.tls
	for len(hs) >= 4 {
		typ := hs[0]
		l := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		if len(hs) < 4+l {
			break
		}
		body := hs[4 : 4+l]
		switch {
		case h.client && typ == 1:
			if hello, ok := parseClientHello(body); ok {
				ti.hello = &hello
				ti.ja3, ti.ja3full = hello.ja3()
				ti.ja4 = hello.ja4(false)
				ti.clientOK = true
				h.e.onTLSClientHello(h.c, ti)
			}
			h.finish()
			return
		case !h.client && typ == 2:
			if ja3s, t13, ok := parseServerHello(body); ok {
				ti.ja3s, ti.tls13 = ja3s, t13
				if t13 {
					h.finish() // certificate is encrypted from here on
					h.e.onTLSServer(h.c, ti)
					return
				}
			}
		case !h.client && typ == 11:
			ti.cert = parseCertificateMsg(body)
			h.finish()
			h.e.onTLSServer(h.c, ti)
			return
		}
		hs = hs[4+l:]
	}
	if end || len(h.buf) > limit {
		if !h.client {
			h.e.onTLSServer(h.c, ti)
		}
		h.finish()
	}
}

func (h *tlsHalf) finish() { h.done, h.buf = true, nil }

// ------------------------------------------------------------- byte reader

type reader struct {
	b   []byte
	bad bool
}

func (r *reader) left() int { return len(r.b) }
func (r *reader) take(n int) []byte {
	if n < 0 || n > len(r.b) {
		r.bad = true
		r.b = nil
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}
func (r *reader) skip(n int) { r.take(n) }
func (r *reader) u8() uint8 {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}
func (r *reader) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
func (r *reader) u24() uint32 {
	b := r.take(3)
	if b == nil {
		return 0
	}
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

// ----------------------------------------------------------- aggregation

// tlsAgg rolls TLS metadata up to a channel.
type tlsAgg struct {
	conns int
	noSNI int
	sni   counts
	ja3   counts
	ja4   counts
	ja3s  counts
	alpn  counts
	tls13 int
	certs map[string]*certInfo // by sha256
}

func (ch *channel) tlsAgg() *tlsAgg {
	if ch.tls == nil {
		ch.tls = &tlsAgg{}
	}
	return ch.tls
}

func (e *Engine) onTLSClientHello(c *tcpConn, ti *tlsInfo) {
	a := c.ch.tlsAgg()
	a.conns++
	if ti.hello.sni == "" {
		a.noSNI++
	} else {
		a.sni.inc(ti.hello.sni)
		if c.tunnelTarget == "" { // a tunnel's SNI names the CONNECT target, not the proxy
			e.addName(c.server.Addr(), ti.hello.sni)
		}
		c.sni = ti.hello.sni
	}
	if c.tunnelTarget != "" {
		t := e.tunnelOf(c)
		if ti.hello.sni != "" {
			t.sni[ti.hello.sni]++
		}
		t.ja4[ti.ja4]++
	}
	a.ja3.inc(ti.ja3)
	a.ja4.inc(ti.ja4)
	for _, p := range ti.hello.alpn {
		a.alpn.inc(p)
	}
	hb := e.hostBaseline(c.client.Addr())
	hb.ja4[ti.ja4]++
	if s := hb.ja4Srv[ti.ja4]; s == nil {
		hb.ja4Srv[ti.ja4] = &ja4Servers{first: c.server}
	} else if !s.multi && s.first != c.server {
		s.multi = true
	}
	hb.tlsConns++
}

func (e *Engine) onTLSServer(c *tcpConn, ti *tlsInfo) {
	if c.tlsServerDone {
		return
	}
	c.tlsServerDone = true
	a := c.ch.tlsAgg()
	if ti.ja3s != "" {
		a.ja3s.inc(ti.ja3s)
	}
	if ti.tls13 {
		a.tls13++
	}
	if ti.cert != nil && len(a.certs) < 8 {
		if a.certs == nil {
			a.certs = map[string]*certInfo{}
		}
		a.certs[ti.cert.SHA256] = ti.cert
	}
	if ti.cert != nil {
		e.sigmaX509(c, ti.cert)
	}
}

// hostBaseline tracks what's normal for one internal host so a channel
// can be judged against it (Netskope-style per-device baseline).
type hostBaseline struct {
	ja4      map[string]int
	ja4Srv   map[string]*ja4Servers // JA4 → servers it was sent to (one, or more)
	tlsConns int
	ua       map[string]int // UA → requests
	uaChans  map[string]*uaDests
}

func (e *Engine) hostBaseline(a interface{ String() string }) *hostBaseline {
	k := a.String()
	hb := e.baselines[k]
	if hb == nil {
		hb = &hostBaseline{ja4: map[string]int{}, ja4Srv: map[string]*ja4Servers{}, ua: map[string]int{}, uaChans: map[string]*uaDests{}}
		e.baselines[k] = hb
	}
	return hb
}

// isQUICLongHeader recognises a QUIC long-header packet (Initial/Handshake)
// for v1, v2 and IETF drafts.
func isQUICLongHeader(p []byte) bool {
	if len(p) < 7 || p[0]&0xc0 != 0xc0 {
		return false
	}
	v := binary.BigEndian.Uint32(p[1:])
	return v == 1 || v == 0x6b3343cf || v&0xffffff00 == 0xff000000 || v == 0
}

// ja4Servers records whether a host sent one JA4 to one server or several
// (v9c 3.3: replaces a per-connection "ja4|server" set and an O(n²) scan).
type ja4Servers struct {
	first netip.AddrPort
	multi bool
}
