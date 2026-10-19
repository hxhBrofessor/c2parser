package engine

import (
	"fmt"
	"strings"

	"c2parser/internal/stats"
)

// Decoded-length residue (v11a M2): the engine side of stats.LengthResidue.
// Per channel and direction it keeps the *decoded* message lengths and an
// aggregate histogram of the decoded bytes; a channel is measured only
// when that aggregate looks encrypted (block-cipher / AEAD framing — free
// text, JSON and DCE/RPC are never measured). QUIC is never measured:
// its packet lengths are padded and coalesced by the transport, so a
// residue there says nothing about the payload (QUIC flows have no
// message-length tracker here at all).
//
// Measured: HTTP request/response bodies and SMB named-pipe messages.
// Decoded length is exact or the message is skipped: raw bodies count as
// themselves; encoded bodies count only when the whole body is in the
// retained prefix and decodes as one run with no wrapper.
//
// Bounded: at most residueMaxMsgs lengths per direction (4 B each) and one
// 256-bin histogram; a direction's tracker is allocated at its second
// eligible message (the first one's length waits in residueFirst), so the
// one-shot request/response connections of a flow-heavy capture never
// allocate one.

const (
	residueMaxMsgs   = 2048
	residueMinRandom = 0.8 // aggregate decoded-bytes randomness to measure
	residueMinBytes  = 512 // … over at least this many decoded bytes
	lengthResidueW   = 0.35
)

// residueRandomGate requires encrypted-looking decoded bytes (mutation hook).
var residueRandomGate = true

// residueTrack is one direction of one channel.
type residueTrack struct {
	lens []int
	hist stats.Histogram
}

func (r *residueTrack) add(n int, decoded []byte, raw *stats.Histogram) {
	if len(r.lens) >= residueMaxMsgs {
		return
	}
	r.lens = append(r.lens, n)
	if decoded != nil {
		r.hist.Add(decoded)
	} else if raw != nil {
		r.hist.Merge(raw)
	}
}

// measure returns the residue class when the direction is measurable and
// its decoded bytes look encrypted.
func (r *residueTrack) measure() (stats.Residue, bool) {
	if r == nil || r.hist.N < residueMinBytes {
		return stats.Residue{}, false
	}
	if a := stats.Assess(&r.hist); residueRandomGate && a.Score < residueMinRandom {
		return stats.Residue{}, false
	}
	return stats.LengthResidue(r.lens)
}

// residuePair is [requests/writes, responses/reads].
type residuePair [2]*residueTrack

func (p *residuePair) track(dir int) *residueTrack {
	if p[dir] == nil {
		p[dir] = &residueTrack{}
	}
	return p[dir]
}

// residueFirst holds, per direction, the length of the first eligible
// message (v11a remediation F06): kept in the channel itself (no
// allocation) until a second eligible message arrives and the tracker is
// allocated, so one-shot connections still never allocate one and the
// first sample still counts. Its bytes are not added to the randomness
// histogram (they were not retained); the length is. 0 = none yet.
type residueFirst [2]int

// observe records one eligible message of direction dir with exact
// decoded length n (decoded bytes or the raw body histogram).
func observeResidue(p **residuePair, first *residueFirst, dir, n int, decoded []byte, raw *stats.Histogram) {
	if n <= 0 {
		return
	}
	if *p == nil || (*p)[dir] == nil {
		if first[dir] == 0 {
			first[dir] = n
			return
		}
		if *p == nil {
			*p = &residuePair{}
		}
		(*p).track(dir).add(first[dir], nil, nil)
		first[dir] = 0
	}
	(*p).track(dir).add(n, decoded, raw)
}

// flushResidueFirst moves pending first lengths into existing trackers
// (after a merge gave a direction a tracker).
func flushResidueFirst(p *residuePair, first *residueFirst) {
	if p == nil {
		return
	}
	for d := range first {
		if first[d] > 0 && p[d] != nil {
			p[d].add(first[d], nil, nil)
			first[d] = 0
		}
	}
}

// noteHTTPResidue records one HTTP message body (v11a M2).
func (ch *httpChannel) noteHTTPResidue(m *httpMsg, opaque bool) {
	if m.bodyLen == 0 || opaque {
		return
	}
	dir := 1
	if m.req {
		dir = 0
	}
	switch {
	case m.bodyLen <= int64(len(m.head)):
		// whole body retained: exact decoded length
		d, enc, pre, suf := decodeUnescaped(strings.TrimSpace(string(m.head)))
		if enc == "raw" {
			observeResidue(&ch.residue, &ch.residueFirst, dir, int(m.bodyLen), nil, &m.hist)
		} else if pre == "" && suf == "" {
			observeResidue(&ch.residue, &ch.residueFirst, dir, len(d), d, nil)
		}
	case m.hist.Classify() == stats.AlphaBinary:
		// longer raw binary body: its length is its decoded length
		observeResidue(&ch.residue, &ch.residueFirst, dir, int(m.bodyLen), nil, &m.hist)
	}
	// longer encoded bodies: the decoded length isn't exact — skipped
}

// notePipeResidue records one SMB pipe message.
func (f *smbFile) notePipeResidue(data []byte, write bool) {
	if len(data) == 0 || len(data) >= 2 && data[0] == 0x05 && data[1] == 0x00 {
		return // DCE/RPC framing is the protocol's, not a payload's
	}
	dir := 1
	if write {
		dir = 0
	}
	observeResidue(&f.residue, &f.residFirst, dir, len(data), data, nil)
}

// lengthResidueSignal returns the neutral signal for the stronger
// direction with a class, if any.
func lengthResidueSignal(p *residuePair, what [2]string) (stats.Signal, bool) {
	if p == nil {
		return stats.Signal{}, false
	}
	var best stats.Residue
	bestDir := -1
	for d, tr := range p {
		r, ok := tr.measure()
		if !ok || r.Mod == 0 {
			continue
		}
		if bestDir < 0 || r.Mod > best.Mod || r.Mod == best.Mod && r.N > best.N {
			best, bestDir = r, d
		}
	}
	if bestDir < 0 {
		return stats.Signal{}, false
	}
	return stats.Signal{Name: "length_residue", Weight: lengthResidueW,
		Score: best.Share * stats.Clamp01(float64(best.Distinct-4)/8),
		Detail: fmt.Sprintf("decoded %s lengths ≡ %d (mod %d) in %.0f%% of %d messages (%d distinct lengths, CV %.2f); encrypted-looking payload",
			what[bestDir], best.Value, best.Mod, best.Share*100, best.N, best.Distinct, best.CV)}, true
}

// mergeResidue folds src into dst (pipe records merged by consolidate).
func mergeResidue(dst, src *residuePair) *residuePair {
	if src == nil {
		return dst
	}
	if dst == nil {
		dst = &residuePair{}
	}
	for d, tr := range src {
		if tr == nil {
			continue
		}
		t := dst.track(d)
		for _, l := range tr.lens {
			if len(t.lens) < residueMaxMsgs {
				t.lens = append(t.lens, l)
			}
		}
		t.hist.Merge(&tr.hist)
	}
	return dst
}
