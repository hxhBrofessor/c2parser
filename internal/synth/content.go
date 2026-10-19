package synth

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand/v2"
	"strings"
)

// Size is a message-size distribution in bytes (decoded payload length).
//
//	fixed    Min
//	uniform  U[Min, Max]
//	normal   N(Mean, SD) clipped to [Min, Max] when set
type Size struct {
	Dist string  `yaml:"dist" json:"dist,omitempty"`
	Min  int     `yaml:"min" json:"min,omitempty"`
	Max  int     `yaml:"max" json:"max,omitempty"`
	Mean float64 `yaml:"mean" json:"mean,omitempty"`
	SD   float64 `yaml:"sd" json:"sd,omitempty"`
}

// Draw returns one size.
func (s Size) Draw(r *rand.Rand) int {
	var n int
	switch s.Dist {
	case "", "fixed":
		n = s.Min
	case "uniform":
		n = s.Min
		if s.Max > s.Min {
			n += r.IntN(s.Max - s.Min + 1)
		}
	case "normal":
		n = int(math.Round(s.Mean + s.SD*r.NormFloat64()))
		if s.Min > 0 && n < s.Min {
			n = s.Min
		}
		if s.Max > 0 && n > s.Max {
			n = s.Max
		}
	}
	return max(n, 0)
}

// Content describes message bodies. Shape labels only: header bytes,
// encoding, XOR key length, padding and decoded-length residue mod 16.
type Content struct {
	Poll     Size      `yaml:"poll" json:"poll"`
	Resp     Size      `yaml:"resp" json:"resp"`
	Encoding string    `yaml:"encoding" json:"encoding,omitempty"` // raw | text | base64 | base64url | base32 | base58 | words | hex | netbios
	Wrap     [2]string `yaml:"wrap" json:"wrap,omitempty"`         // constant prepend / append around the *encoded* body (v11a)
	Header   string    `yaml:"header" json:"header,omitempty"`     // hex bytes at the start of every decoded body
	XORKey   int       `yaml:"xor_key" json:"xor_key,omitempty"`   // > 0: ASCII plaintext XORed with a repeating key of this length
	Pad      [2]int    `yaml:"pad" json:"pad,omitempty"`           // random padding U[Pad[0], Pad[1]]
	Residue  string    `yaml:"residue" json:"residue,omitempty"`   // "" | "0" | "4" | "12" | "uniform": decoded length mod 16
	Method   string    `yaml:"method" json:"method,omitempty"`     // HTTP method (GET: poll body goes in the URI)
	URI      string    `yaml:"uri" json:"uri,omitempty"`
	Headers  []string  `yaml:"headers" json:"headers,omitempty"`
	ALPN     []string  `yaml:"alpn" json:"alpn,omitempty"`
	TLS      string    `yaml:"tls" json:"tls,omitempty"`         // "1.3" (default) | "1.2"
	QType    string    `yaml:"qtype" json:"qtype,omitempty"`     // dns: A | TXT | AAAA
	Framing  string    `yaml:"framing" json:"framing,omitempty"` // tcp-pivot: le32 | be32 | be12
	Preset   string    `yaml:"preset" json:"preset,omitempty"`   // ldap: recon | acl-sweep | aduc | logon; dcerpc-tcp: wmi-exec | epm-drsuapi
	SASL     string    `yaml:"sasl" json:"sasl,omitempty"`       // ldap: "" plain | ntlm | krb (Kerberos-signed, RRC 12)
}

// keyed holds per-stream content state (the XOR key is fixed per stream).
type keyed struct {
	c   Content
	key []byte
	hdr []byte
}

func newKeyed(c Content, r *rand.Rand) (*keyed, error) {
	k := &keyed{c: c}
	if c.Header != "" {
		h, err := hex.DecodeString(strings.ReplaceAll(c.Header, " ", ""))
		if err != nil {
			return nil, fmt.Errorf("content header: %w", err)
		}
		k.hdr = h
	}
	if c.XORKey > 0 {
		k.key = RandBytes(r, c.XORKey)
	}
	switch c.Encoding {
	case "", "raw", "text", "base64", "base64url", "base32", "base58", "words", "hex", "netbios":
	default:
		return nil, fmt.Errorf("unknown encoding %q", c.Encoding)
	}
	switch c.Residue {
	case "", "0", "4", "12", "uniform":
	default:
		return nil, fmt.Errorf("unknown residue class %q", c.Residue)
	}
	return k, nil
}

// decoded builds one decoded body of about n bytes.
func (k *keyed) decoded(r *rand.Rand, n int) []byte {
	if k.c.Pad[1] > 0 {
		n += k.c.Pad[0] + r.IntN(max(1, k.c.Pad[1]-k.c.Pad[0]+1))
	}
	total := len(k.hdr) + n
	want := -1
	switch k.c.Residue {
	case "0":
		want = 0
	case "4":
		want = 4
	case "12":
		want = 12
	}
	if want >= 0 {
		total += ((want-total)%16 + 16) % 16
		n = total - len(k.hdr)
	}
	var p []byte
	if k.c.Encoding == "text" {
		p = textBytes(r, n)
	} else if k.key != nil {
		const plain = "status=ok;id=0042;q=queue;cmd=none;data="
		p = make([]byte, n)
		for i := range p {
			p[i] = plain[i%len(plain)] ^ k.key[i%len(k.key)]
		}
	} else {
		p = RandBytes(r, n)
	}
	return append(append([]byte{}, k.hdr...), p...)
}

// Encode applies the content encoding and the constant wrapper.
func (k *keyed) encode(b []byte) []byte {
	e := k.encodeOnly(b)
	if k.c.Wrap != [2]string{} {
		e = append(append([]byte(k.c.Wrap[0]), e...), k.c.Wrap[1]...)
	}
	return e
}

func (k *keyed) encodeOnly(b []byte) []byte {
	switch k.c.Encoding {
	case "base64":
		return []byte(base64.StdEncoding.EncodeToString(b))
	case "base64url":
		return []byte(base64.RawURLEncoding.EncodeToString(b))
	case "base32":
		return []byte(strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)))
	case "base58":
		return []byte(Base58(b))
	case "words":
		return []byte(Words(b))
	case "hex":
		return []byte(hex.EncodeToString(b))
	case "netbios":
		out := make([]byte, 0, 2*len(b))
		for _, c := range b {
			out = append(out, 'a'+c>>4, 'a'+c&0x0f)
		}
		return out
	}
	return b
}

// Body returns an encoded body of about n decoded bytes.
func (k *keyed) body(r *rand.Rand, n int) []byte { return k.encode(k.decoded(r, n)) }

// Frame wraps a pivot message in its length framing.
func Frame(framing string, msg []byte) []byte {
	n := uint32(len(msg))
	switch framing {
	case "le32":
		return append([]byte{byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}, msg...)
	case "be12": // 12-byte big-endian chunk header: length, chunk index, chunk count
		h := []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n), 0, 0, 0, 0, 0, 0, 0, 1}
		return append(h, msg...)
	default: // be32
		return append([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, msg...)
	}
}

// MagicFramed is a positional-framing shape: a 4-byte big-endian length,
// a 4-byte magic and a 4-byte id, then n random bytes.
func MagicFramed(r *rand.Rand, magic, id uint32, n int) []byte {
	p := make([]byte, 12, 12+n)
	l := uint32(8 + n)
	p[0], p[1], p[2], p[3] = byte(l>>24), byte(l>>16), byte(l>>8), byte(l)
	p[4], p[5], p[6], p[7] = byte(magic>>24), byte(magic>>16), byte(magic>>8), byte(magic)
	p[8], p[9], p[10], p[11] = byte(id>>24), byte(id>>16), byte(id>>8), byte(id)
	return append(p, RandBytes(r, n)...)
}

// textBytes is low-entropy ASCII (metrics-exposition-like lines) for
// benign bodies.
func textBytes(r *rand.Rand, n int) []byte {
	words := []string{"node_cpu_seconds_total", "mode", "idle", "user", "system", "cpu", "go_gc_duration_seconds",
		"quantile", "process_resident_memory_bytes", "http_requests_total", "code", "200", "method", "get", "Package:", "Version:", "Architecture:", "amd64", "Depends:"}
	var b []byte
	for len(b) < n {
		w := words[r.IntN(len(words))]
		b = append(b, w...)
		b = append(b, '{')
		b = append(b, words[r.IntN(len(words))]...)
		b = append(b, fmt.Sprintf("=\"%d\"} %d.%02d\n", r.IntN(16), r.IntN(100000), r.IntN(100))...)
	}
	return b[:n]
}
