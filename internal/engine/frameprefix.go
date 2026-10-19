package engine

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"

	"c2parser/internal/stats"
)

// Unknown-but-constant pivot frame headers (v11a N3). A pivot channel
// (SMB named pipe) whose messages all start with the same 4 bytes — at
// offset 0, or at offset 4 right after a length field — is framing its
// messages with a header nobody here has a name for. Known magics
// (knownFrameMagics) keep c2_framing_in_pipe; this neutral signal,
// pivot_frame_header, covers the rest. No attribution.
//
// Bounded: per pipe and direction, at most framePrefixMaxCands distinct
// candidate values per offset are counted (later new values only bump the
// total), so a pipe of random data costs a few hundred bytes.

const (
	framePrefixMinMsgs  = 8
	framePrefixMinFrac  = 0.9
	framePrefixMaxCands = 16
	pivotFrameWeight    = 0.45
)

// pivotFrames enables pivot_frame_header (mutation hook: off = only the
// literal known magics count, as in v10).
var pivotFrames = true

// frameOffsets are where a constant header is looked for.
var frameOffsets = [...]int{0, 4}

type prefixCounts struct {
	n      int // messages long enough to carry this offset
	counts map[[4]byte]int
}

func (p *prefixCounts) add(v [4]byte) {
	p.n++
	if p.counts == nil {
		p.counts = map[[4]byte]int{}
	}
	if _, ok := p.counts[v]; ok || len(p.counts) < framePrefixMaxCands {
		p.counts[v]++
	}
}

// best returns the most frequent candidate (ties: smallest value, for
// determinism) and its count.
func (p *prefixCounts) best() ([4]byte, int) {
	var bv [4]byte
	bn := 0
	keys := make([][4]byte, 0, len(p.counts))
	for k := range p.counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return string(keys[i][:]) < string(keys[j][:]) })
	for _, k := range keys {
		if c := p.counts[k]; c > bn {
			bv, bn = k, c
		}
	}
	return bv, bn
}

// frameTrack: [direction write=0/read=1][offset index].
type frameTrack [2][len(frameOffsets)]prefixCounts

// observe records one pipe message.
func (t *frameTrack) observe(data []byte, write bool) {
	if len(data) >= 2 && data[0] == 0x05 && data[1] == 0x00 {
		return // DCE/RPC (v5.0) over the pipe: its constant header is the protocol
	}
	d := 1
	if write {
		d = 0
	}
	for i, off := range frameOffsets {
		if len(data) < off+4+4 { // header plus at least 4 bytes of payload
			continue
		}
		var v [4]byte
		copy(v[:], data[off:off+4])
		if lengthLike(v, len(data)) {
			continue // a length field, not a constant header
		}
		t[d][i].add(v)
	}
}

// lengthLike: v encodes the message length (± the 4-byte field itself),
// little- or big-endian.
func lengthLike(v [4]byte, n int) bool {
	for _, x := range []uint32{binary.LittleEndian.Uint32(v[:]), binary.BigEndian.Uint32(v[:])} {
		if x == uint32(n) || x == uint32(n-4) || x == uint32(n-8) {
			return true
		}
	}
	return false
}

// merge folds another track in (pipe records merged by consolidate).
//
// v11a remediation F05: the union of both candidate tables is ranked by
// count (descending), ties by byte value (ascending), and the top
// framePrefixMaxCands are kept — deterministic, independent of Go map
// iteration order, and a dominant incoming candidate always survives.
// Approximation (stated): counts of candidates that fall out of the
// bounded table are dropped (they still count in n), exactly as add()
// drops values first seen after the table is full.
func (t *frameTrack) merge(o *frameTrack) {
	if o == nil {
		return
	}
	for d := range t {
		for i := range t[d] {
			src, dst := &o[d][i], &t[d][i]
			dst.n += src.n
			if len(src.counts) == 0 {
				continue
			}
			union := make(map[[4]byte]int, len(dst.counts)+len(src.counts))
			for k, c := range dst.counts {
				union[k] += c
			}
			for k, c := range src.counts {
				union[k] += c
			}
			keys := make([][4]byte, 0, len(union))
			for k := range union {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(a, b int) bool {
				if union[keys[a]] != union[keys[b]] {
					return union[keys[a]] > union[keys[b]]
				}
				return string(keys[a][:]) < string(keys[b][:])
			})
			if len(keys) > framePrefixMaxCands {
				keys = keys[:framePrefixMaxCands]
			}
			dst.counts = make(map[[4]byte]int, len(keys))
			for _, k := range keys {
				dst.counts[k] = union[k]
			}
		}
	}
}

// constantHeader is the strongest constant header across directions and
// offsets, or ok=false.
type constantHeader struct {
	value     [4]byte
	offset    int
	dir       string
	hits, msg int
}

func (t *frameTrack) constant() (constantHeader, bool) {
	var best constantHeader
	found := false
	for d := range t {
		for i, off := range frameOffsets {
			p := &t[d][i]
			if p.n < framePrefixMinMsgs {
				continue
			}
			v, c := p.best()
			if v == [4]byte{} || v == [4]byte{0xff, 0xff, 0xff, 0xff} {
				continue
			}
			if float64(c) < framePrefixMinFrac*float64(p.n) {
				continue
			}
			ch := constantHeader{v, off, map[int]string{0: "writes", 1: "reads"}[d], c, p.n}
			if !found || c > best.hits || c == best.hits && off < best.offset {
				best, found = ch, true
			}
		}
	}
	return best, found
}

// pivotFrameSignal turns a constant header into the neutral signal; the
// (n-4)/8 ramp mirrors the carrier variability guard (8 messages → 0.5,
// 12+ → 1).
func pivotFrameSignal(h constantHeader) stats.Signal {
	frac := float64(h.hits) / float64(h.msg)
	return stats.Signal{Name: "pivot_frame_header", Weight: pivotFrameWeight,
		Score: frac * stats.Clamp01(float64(h.msg-4)/8),
		Detail: fmt.Sprintf("%d/%d pipe %s start with the same 4 bytes %s at offset %d (unknown constant frame header)",
			h.hits, h.msg, h.dir, hex.EncodeToString(h.value[:]), h.offset)}
}
