package engine

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"time"
)

// LDAP SearchRequest parsing for AD reconnaissance (v10a 2.2). Plain LDAP
// and SASL-wrapped LDAP (GSS-SPNEGO with NTLM or Kerberos signing) are
// read; a sealed wrap gives volume only. Only requests (base, scope,
// filter, attributes, controls) and result-entry counts are kept — never
// the returned attribute values.

// ------------------------------------------------------------------ BER

type berTLV struct {
	tag         byte
	constructed bool
	val         []byte
}

// berNext reads one TLV (definite lengths only, ≤ 4 length octets).
func berNext(b []byte) (t berTLV, rest []byte, ok bool) {
	if len(b) < 2 {
		return t, nil, false
	}
	t.tag = b[0]
	t.constructed = b[0]&0x20 != 0
	if b[0]&0x1f == 0x1f {
		return t, nil, false // multi-byte tags are not used by LDAP
	}
	l := int(b[1])
	p := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || len(b) < 2+n {
			return t, nil, false
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(b[2+i])
		}
		p += n
	}
	if l < 0 || l > len(b)-p {
		return t, nil, false
	}
	return berTLV{tag: b[0], constructed: b[0]&0x20 != 0, val: b[p : p+l]}, b[p+l:], true
}

// berLen is the full length of the TLV at the start of b (−1 if unknown,
// 0 if more bytes are needed).
func berLen(b []byte) int {
	if len(b) < 2 {
		return 0
	}
	l := int(b[1])
	p := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 {
			return -1
		}
		if len(b) < 2+n {
			return 0
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(b[2+i])
		}
		p += n
	}
	if l > 16<<20 {
		return -1
	}
	return p + l
}

func berInt(v []byte) int64 {
	var n int64
	for i, c := range v {
		if i == 0 && c&0x80 != 0 {
			n = -1
		}
		n = n<<8 | int64(c)
	}
	return n
}

// ------------------------------------------------------------------ filters

// ldapFacts are what recon scoring reads from a filter.
type ldapFacts struct {
	attrs      map[string]bool // every attribute named in the filter (lower case)
	present    map[string]bool // attr=*
	equals     map[string][]string
	uacBits    []int64 // values in :1.2.840.113556.1.4.803/804: bit tests on userAccountControl
	classes    []string
	narrowed   bool // an equality on an identity attribute (sAMAccountName, cn, objectSid, DN, GUID …)
	extensible int
}

var identityAttrs = map[string]bool{"samaccountname": true, "cn": true, "name": true, "distinguishedname": true, "objectsid": true,
	"objectguid": true, "userprincipalname": true, "dnshostname": true, "serviceprincipalname": true, "displayname": true}

// renderFilter decodes a Filter (RFC 4511 §4.5.1) to RFC 4515 text and
// collects facts. depth bounds recursion.
func renderFilter(t berTLV, f *ldapFacts, depth int) string {
	if depth > 32 {
		return "…"
	}
	pair := func() (string, string, bool) {
		a, r, ok := berNext(t.val)
		if !ok {
			return "", "", false
		}
		v, _, ok := berNext(r)
		if !ok {
			return "", "", false
		}
		return string(a.val), string(v.val), true
	}
	switch t.tag {
	case 0xa0, 0xa1: // and, or
		var parts []string
		for rest := t.val; len(rest) > 0 && len(parts) < 64; {
			c, r, ok := berNext(rest)
			if !ok {
				break
			}
			parts = append(parts, renderFilter(c, f, depth+1))
			rest = r
		}
		op := "&"
		if t.tag == 0xa1 {
			op = "|"
		}
		return "(" + op + strings.Join(parts, "") + ")"
	case 0xa2: // not
		c, _, ok := berNext(t.val)
		if !ok {
			return "(!?)"
		}
		return "(!" + renderFilter(c, f, depth+1) + ")"
	case 0xa3, 0xa5, 0xa6, 0xa8: // equality, >=, <=, ~=
		a, v, ok := pair()
		if !ok {
			return "(?)"
		}
		al := strings.ToLower(a)
		f.attrs[al] = true
		op := map[byte]string{0xa3: "=", 0xa5: ">=", 0xa6: "<=", 0xa8: "~="}[t.tag]
		if t.tag == 0xa3 {
			f.equals[al] = append(f.equals[al], v)
			if al == "objectclass" || al == "objectcategory" {
				f.classes = append(f.classes, strings.ToLower(v))
			}
			if identityAttrs[al] && v != "*" {
				f.narrowed = true
			}
		}
		return "(" + a + op + printable(v) + ")"
	case 0xa4: // substrings
		a, r, ok := berNext(t.val)
		if !ok {
			return "(?)"
		}
		al := strings.ToLower(string(a.val))
		f.attrs[al] = true
		s := "(" + string(a.val) + "="
		seq, _, ok := berNext(r)
		if ok {
			for rest := seq.val; len(rest) > 0; {
				c, rr, ok := berNext(rest)
				if !ok {
					break
				}
				s += map[byte]string{0x80: "", 0x81: "*", 0x82: "*"}[c.tag] + printable(string(c.val))
				if c.tag == 0x80 || c.tag == 0x81 {
					s += "*"
				}
				rest = rr
			}
		}
		if identityAttrs[al] {
			f.narrowed = true
		}
		return s + ")"
	case 0x87: // present
		a := strings.ToLower(string(t.val))
		f.attrs[a] = true
		f.present[a] = true
		return "(" + string(t.val) + "=*)"
	case 0xa9: // extensibleMatch
		var rule, typ, val string
		for rest := t.val; len(rest) > 0; {
			c, r, ok := berNext(rest)
			if !ok {
				break
			}
			switch c.tag {
			case 0x81:
				rule = string(c.val)
			case 0x82:
				typ = string(c.val)
			case 0x83:
				val = string(c.val)
			}
			rest = r
		}
		f.extensible++
		tl := strings.ToLower(typ)
		f.attrs[tl] = true
		if tl == "useraccountcontrol" && (rule == "1.2.840.113556.1.4.803" || rule == "1.2.840.113556.1.4.804") {
			var n int64
			fmt.Sscanf(val, "%d", &n)
			f.uacBits = append(f.uacBits, n)
		}
		return "(" + typ + ":" + rule + ":=" + printable(val) + ")"
	}
	return "(?)"
}

func printable(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			return fmt.Sprintf("\\%x", b[:min(len(b), 24)]) // binary value (SID, GUID): hex
		}
		_ = i
	}
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

// ------------------------------------------------------------------ session

// ldapSearch is one distinct search (same base/scope/filter/attrs).
type ldapSearch struct {
	base, filter string
	scope        int64
	attrs        []string
	controls     []string
	facts        ldapFacts
	count        int  // requests
	entries      int  // SearchResultEntry responses
	pages        int  // requests carrying a non-empty paged-results cookie
	completed    bool // a SearchResultDone with resultCode success was seen (the whole set came back)
	first        time.Time
	frame        int64
}

const (
	oidSDFlags = "1.2.840.113556.1.4.801"
	oidPaged   = "1.2.840.113556.1.4.319"
)

type ldapSession struct {
	c        *tcpConn
	cbuf     []byte
	sbuf     []byte
	byKey    map[string]*ldapSearch
	order    []*ldapSearch
	pending  map[int64]*ldapSearch
	sealed   bool
	sealedB  int64
	messages int
}

func (e *Engine) newLDAPSession(c *tcpConn) *ldapSession {
	s := &ldapSession{c: c, byKey: map[string]*ldapSearch{}, pending: map[int64]*ldapSearch{}}
	e.ldapSessions = append(e.ldapSessions, s)
	return s
}

// looksLDAP: an LDAPMessage (SEQUENCE, INTEGER messageID) or a SASL
// length prefix followed by one.
func looksLDAP(b []byte) bool {
	if len(b) < 7 || b[0] != 0x30 || berLen(b) < 0 {
		return false
	}
	p := 2
	if b[1]&0x80 != 0 {
		p += int(b[1] & 0x7f)
	}
	// messageID INTEGER (1–4 bytes), then an application-tagged protocolOp
	if p+1 >= len(b) || b[p] != 0x02 || b[p+1] < 1 || b[p+1] > 4 {
		return false
	}
	q := p + 2 + int(b[p+1])
	return q < len(b) && b[q]&0xe0 == 0x60
}

type ldapHalf struct {
	e      *Engine
	s      *ldapSession
	client bool
}

func (h *ldapHalf) gap() {
	if h.client {
		h.s.cbuf = nil
	} else {
		h.s.sbuf = nil
	}
}
func (h *ldapHalf) close(time.Time) {}

func (h *ldapHalf) feed(data []byte, ts time.Time, frame int64) {
	buf := &h.s.sbuf
	if h.client {
		buf = &h.s.cbuf
	}
	*buf = append(*buf, data...)
	for len(*buf) > 0 {
		b := *buf
		if b[0] == 0x30 {
			n := berLen(b)
			if n < 0 {
				*buf = nil
				return
			}
			if n == 0 || n > len(b) {
				if len(b) > 1<<22 {
					*buf = nil
				}
				return
			}
			h.message(b[:n], ts, frame)
			*buf = b[n:]
			continue
		}
		// SASL buffer: 4-byte big-endian length
		if len(b) < 4 {
			return
		}
		l := int(binary.BigEndian.Uint32(b))
		if l < 16 || l > 1<<24 {
			*buf = nil
			return
		}
		if len(b) < 4+l {
			return
		}
		h.sasl(b[4:4+l], ts, frame)
		*buf = b[4+l:]
	}
}

// sasl unwraps one SASL buffer: NTLM-signed (16-byte signature first),
// Kerberos GSS wrap token v2 (05 04; flag 0x02 = sealed), or plain.
func (h *ldapHalf) sasl(p []byte, ts time.Time, frame int64) {
	inner := p
	switch {
	case len(p) >= 16 && p[0] == 0x05 && p[1] == 0x04: // RFC 4121 wrap token
		if p[2]&0x02 != 0 {
			h.sealedData(len(p))
			return
		}
		ec := int(binary.BigEndian.Uint16(p[4:]))
		rrc := int(binary.BigEndian.Uint16(p[6:]))
		inner = p[16:]
		if rrc > 0 && len(inner) > 0 && undoRRC { // RFC 4121 §4.2.5: undo the right rotation (Windows: RRC = EC)
			r := rrc % len(inner)
			inner = append(append([]byte{}, inner[r:]...), inner[:r]...)
		}
		if ec <= len(inner) {
			inner = inner[:len(inner)-ec] // checksum trails the data
		}
	case len(p) >= 16 && binary.LittleEndian.Uint32(p) == 1: // NTLMSSP signature (version 1)
		inner = p[16:]
	}
	if len(inner) == 0 || inner[0] != 0x30 {
		h.sealedData(len(p))
		return
	}
	for len(inner) > 0 {
		n := berLen(inner)
		if n <= 0 || n > len(inner) {
			return
		}
		h.message(inner[:n], ts, frame)
		inner = inner[n:]
	}
}

// undoRRC undoes the RFC 4121 right rotation (mutation hook, v10a.1).
var undoRRC = true

func (h *ldapHalf) sealedData(n int) {
	h.s.sealed = true
	h.s.sealedB += int64(n)
}

// message handles one LDAPMessage.
func (h *ldapHalf) message(m []byte, ts time.Time, frame int64) {
	seq, _, ok := berNext(m)
	if !ok || seq.tag != 0x30 {
		return
	}
	id, rest, ok := berNext(seq.val)
	if !ok || id.tag != 0x02 {
		return
	}
	msgID := berInt(id.val)
	op, rest, ok := berNext(rest)
	if !ok {
		return
	}
	s := h.s
	s.messages++
	switch {
	case h.client && op.tag == 0x63: // SearchRequest
		if len(s.byKey) >= 2000 {
			return
		}
		sr := parseSearch(op.val)
		if ctl, _, ok := berNext(rest); ok && ctl.tag == 0xa0 {
			sr.controls, sr.pages = parseControls(ctl.val)
		}
		key := fmt.Sprintf("%s|%d|%s|%s", strings.ToLower(sr.base), sr.scope, sr.filter, strings.Join(sr.attrs, ","))
		x := s.byKey[key]
		if x == nil {
			x = sr
			x.first, x.frame = ts, frame
			s.byKey[key] = x
			s.order = append(s.order, x)
		} else {
			x.pages += sr.pages
		}
		x.count++
		if len(s.pending) < 4096 {
			s.pending[msgID] = x
		}
	case !h.client && op.tag == 0x64: // SearchResultEntry
		if x := s.pending[msgID]; x != nil {
			x.entries++
		}
	case !h.client && op.tag == 0x65: // SearchResultDone
		if x := s.pending[msgID]; x != nil {
			if rc, _, ok := berNext(op.val); ok && rc.tag == 0x0a && berInt(rc.val) == 0 {
				x.completed = true // success, not sizeLimitExceeded (4) or an error
			}
		}
		delete(s.pending, msgID)
	}
}

func parseSearch(v []byte) *ldapSearch {
	sr := &ldapSearch{facts: ldapFacts{attrs: map[string]bool{}, present: map[string]bool{}, equals: map[string][]string{}}}
	base, r, ok := berNext(v)
	if !ok {
		return sr
	}
	sr.base = printable(string(base.val))
	scope, r, ok := berNext(r)
	if !ok {
		return sr
	}
	sr.scope = berInt(scope.val)
	for i := 0; i < 4; i++ { // derefAliases, sizeLimit, timeLimit, typesOnly
		if _, r, ok = berNext(r); !ok {
			return sr
		}
	}
	flt, r, ok := berNext(r)
	if !ok {
		return sr
	}
	sr.filter = renderFilter(flt, &sr.facts, 0)
	if attrs, _, ok := berNext(r); ok {
		for rest := attrs.val; len(rest) > 0 && len(sr.attrs) < 64; {
			a, rr, ok := berNext(rest)
			if !ok {
				break
			}
			sr.attrs = append(sr.attrs, string(a.val))
			rest = rr
		}
	}
	return sr
}

// parseControls returns control OIDs and 1 if a paged-results control
// carries a non-empty cookie (a follow-up page).
func parseControls(v []byte) (oids []string, page int) {
	for rest := v; len(rest) > 0 && len(oids) < 16; {
		c, r, ok := berNext(rest)
		if !ok {
			break
		}
		rest = r
		oid, cr, ok := berNext(c.val)
		if !ok {
			continue
		}
		o := string(oid.val)
		oids = append(oids, o)
		if o == oidPaged {
			for len(cr) > 0 {
				x, rr, ok := berNext(cr)
				if !ok {
					break
				}
				cr = rr
				if x.tag == 0x04 { // controlValue: SEQUENCE { size, cookie }
					if pv, _, ok := berNext(x.val); ok {
						_, rr2, ok := berNext(pv.val)
						if ok {
							if cookie, _, ok := berNext(rr2); ok && len(cookie.val) > 0 {
								page = 1
							}
						}
					}
				}
			}
		}
	}
	return oids, page
}

// sortedSearches is a session's searches in first-seen order.
func (s *ldapSession) searches() []*ldapSearch {
	out := append([]*ldapSearch(nil), s.order...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].first.Before(out[j].first) })
	return out
}
