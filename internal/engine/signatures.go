package engine

import (
	"bytes"
	"encoding/binary"
)

// signature identifies a payload by its first bytes. These are deliberately
// structural (framing / file magic), not hashes, so they survive per-build
// key changes.
type signature struct {
	Name   string
	Kind   string  // "c2" | "tooling" | "archive"
	Weight float64 // how much one hit alone should convince us
	match  func(head []byte) bool
}

var signatures = []signature{
	{
		// Havoc Demon packet: [u32 size BE][u32 0xDEADBEEF][u32 agent id]...
		Name: "havoc-demon-header", Kind: "c2", Weight: 0.97,
		match: func(h []byte) bool {
			if len(h) < 12 {
				return false
			}
			size := binary.BigEndian.Uint32(h)
			return binary.BigEndian.Uint32(h[4:]) == 0xDEADBEEF && size >= 8 && size < 64<<20
		},
	},
	{
		Name: "pe-executable", Kind: "tooling", Weight: 0.6,
		match: func(h []byte) bool {
			if len(h) < 0x40 || h[0] != 'M' || h[1] != 'Z' {
				return false
			}
			off := int(binary.LittleEndian.Uint32(h[0x3c:]))
			return off+4 <= len(h) && bytes.Equal(h[off:off+4], []byte("PE\x00\x00"))
		},
	},
	{
		Name: "elf-executable", Kind: "tooling", Weight: 0.5,
		match: func(h []byte) bool { return bytes.HasPrefix(h, []byte("\x7fELF")) },
	},
	{
		Name: "zip-archive", Kind: "archive", Weight: 0.35,
		match: func(h []byte) bool { return bytes.HasPrefix(h, []byte("PK\x03\x04")) },
	},
	{
		Name: "7z-archive", Kind: "archive", Weight: 0.45,
		match: func(h []byte) bool { return bytes.HasPrefix(h, []byte("7z\xbc\xaf\x27\x1c")) },
	},
	{
		Name: "rar-archive", Kind: "archive", Weight: 0.45,
		match: func(h []byte) bool { return bytes.HasPrefix(h, []byte("Rar!\x1a\x07")) },
	},
}

// matchSignatures returns every signature that fires on head.
func matchSignatures(head []byte) []signature {
	var out []signature
	for _, s := range signatures {
		if s.match(head) {
			out = append(out, s)
		}
	}
	return out
}

// knownFrameMagics is the table of known C2 frame magics (v11a N3; a Go
// constant here, the v11b profile YAML later). Each sits right after a
// 4-byte big-endian length: Havoc Demon [u32 size][0xDEADBEEF][agent id].
var knownFrameMagics = [][]byte{{0xde, 0xad, 0xbe, 0xef}}

// containsC2Magic scans a whole buffer (not just its head) for framing
// that has been embedded in another protocol, e.g. Havoc inside SMB pipe
// reads. Returns the number of hits.
func containsC2Magic(b []byte) int {
	n, _ := containsFramePrefix(b, knownFrameMagics)
	return n
}

// containsFramePrefix generalises containsC2Magic over a table of frame
// magics: it counts occurrences of any prefix that follow a plausible
// big-endian length (8 B … 64 MB), and returns the first prefix that hit.
// With the one-entry table it counts exactly what v10's 0xDEADBEEF scan did.
func containsFramePrefix(b []byte, prefixes [][]byte) (hits int, which []byte) {
	for _, magic := range prefixes {
		if len(magic) == 0 {
			continue
		}
		n := 0
		for i := 0; ; {
			j := bytes.Index(b[i:], magic)
			if j < 0 {
				break
			}
			pos := i + j
			if pos >= 4 {
				size := binary.BigEndian.Uint32(b[pos-4:])
				if size >= 8 && size < 64<<20 {
					n++
				}
			}
			i = pos + len(magic)
		}
		if n > 0 && which == nil {
			which = magic
		}
		hits += n
	}
	return hits, which
}
