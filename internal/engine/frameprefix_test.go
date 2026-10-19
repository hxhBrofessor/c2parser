package engine

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	sy "c2parser/internal/synth"
)

// containsC2MagicV10 is c2parser-v10.0 containsC2Magic verbatim, the
// reference for "the known-magic path is unchanged".
func containsC2MagicV10(b []byte) int {
	n := 0
	magic := []byte{0xde, 0xad, 0xbe, 0xef}
	for i := 0; ; {
		j := bytes.Index(b[i:], magic)
		if j < 0 {
			return n
		}
		pos := i + j
		if pos >= 4 {
			size := binary.BigEndian.Uint32(b[pos-4:])
			if size >= 8 && size < 64<<20 {
				n++
			}
		}
		i = pos + 4
	}
}

func FuzzContainsFramePrefix(f *testing.F) {
	f.Add([]byte{})
	f.Add(havocPacket(40))
	f.Add(append(havocPacket(10), havocPacket(3)...))
	f.Add([]byte{0, 0, 0, 9, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef})
	f.Fuzz(func(t *testing.T, b []byte) {
		if got, want := containsC2Magic(b), containsC2MagicV10(b); got != want {
			t.Fatalf("containsC2Magic %d, v10 %d", got, want)
		}
		hits, which := containsFramePrefix(b, [][]byte{{0xde, 0xad, 0xbe, 0xef}, {0xc0, 0xff, 0xee, 0x01}, nil})
		if hits < containsC2MagicV10(b) || hits > 0 && which == nil || hits == 0 && which != nil {
			t.Fatalf("hits %d which %x", hits, which)
		}
		var tr frameTrack
		tr.observe(b, len(b)%2 == 0) // never panics on any message
		tr.constant()
	})
}

func TestContainsFramePrefixTable(t *testing.T) {
	p := append(append(havocPacket(20), sy.Frame("be32", append([]byte{0xc0, 0xff, 0xee, 0x01}, make([]byte, 20)...))...), havocPacket(5)...)
	if n, w := containsFramePrefix(p, knownFrameMagics); n != 2 || !bytes.Equal(w, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("known table: %d %x", n, w)
	}
	if n, w := containsFramePrefix(p, [][]byte{{0xc0, 0xff, 0xee, 0x01}}); n != 1 || w[0] != 0xc0 {
		t.Errorf("custom table: %d %x", n, w)
	}
}

// pipeChannel writes n write/read pairs on a named pipe to 10.9.0.30.
func pipeChannel(t *testing.T, name string, n int, msg func(i int, write bool) []byte) *Result {
	t.Helper()
	s := newSynth(t)
	r := seeded(101, 102)
	ts := s.now
	p, ts := s.b.OpenPipe(ts, "10.9.0.22", 49800, "10.9.0.30", name, 9)
	for i := 0; i < n; i++ {
		ts = ts.Add(time.Duration(8+r.IntN(5)) * time.Second)
		ts = p.Write(ts, msg(i, true))
		ts = p.Read(ts.Add(5*time.Millisecond), msg(i, false))
	}
	p.T.Close(ts.Add(time.Second))
	return s.analyze(Config{})
}

func pipeSignal(res *Result, name, sig string) (*Finding, bool) {
	for i := range res.Findings {
		f := &res.Findings[i]
		if f.Category != CatPipe || !strings.Contains(f.Title, name) {
			continue
		}
		for _, s := range f.Signals {
			if s.Name == sig {
				return f, true
			}
		}
		return f, false
	}
	return nil, false
}

func TestPivotFrameHeader(t *testing.T) {
	r := seeded(111, 112)
	hdr := []byte{0x7a, 0x31, 0x9c, 0x04} // invented, not a known magic
	invented := func(off int) func(int, bool) []byte {
		return func(i int, w bool) []byte {
			body := rbytes(r, 30+r.IntN(200))
			if off == 0 {
				return append(append([]byte{}, hdr...), body...)
			}
			m := append(append([]byte{}, hdr...), body...)
			return sy.Frame("le32", m) // [len LE32][hdr][body]
		}
	}
	for _, tc := range []struct {
		name string
		pipe string
		n    int
		msg  func(int, bool) []byte
		want bool
	}{
		{"invented prefix at offset 0", "svcctl_x", 12, invented(0), true},
		{"invented prefix after a length field", "updsvc", 12, invented(4), true},
		{"7 messages per direction: below the floor", "updsvc2", 7, invented(0), false},
		{"8 messages per direction: at the floor", "updsvc3", 8, invented(0), true},
		{"random pipe data", "rndsvc", 12, func(int, bool) []byte { return rbytes(r, 40+r.IntN(200)) }, false},
		{"length-prefixed random data", "lensvc", 12, func(int, bool) []byte { return sy.Frame("le32", rbytes(r, 40+r.IntN(200))) }, false},
		{"DCE/RPC on an unknown pipe", "dcesvc", 12, func(i int, w bool) []byte {
			return append([]byte{0x05, 0x00, 0x00, 0x03, 0x10, 0, 0, 0}, rbytes(r, 60)...)
		}, false},
		{"constant header on a standard Windows pipe", "srvsvc", 12, invented(0), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := pipeChannel(t, tc.pipe, tc.n, tc.msg)
			f, got := pipeSignal(res, tc.pipe, "pivot_frame_header")
			if got != tc.want {
				t.Fatalf("pivot_frame_header=%v, want %v: %v", got, tc.want, f)
			}
		})
	}
	// Havoc framing keeps c2_framing_in_pipe and is not double-counted
	res := pipeChannel(t, "gainz", 12, func(int, bool) []byte { return havocPacket(60 + r.IntN(100)) })
	if _, ok := pipeSignal(res, "gainz", "c2_framing_in_pipe"); !ok {
		t.Error("Havoc pipe lost c2_framing_in_pipe")
	}
	if _, ok := pipeSignal(res, "gainz", "pivot_frame_header"); ok {
		t.Error("Havoc pipe also fired pivot_frame_header")
	}
}

// Corpus gate + mutation: shape-smb-pipe-framed (invented header
// c0ffee01) fires pivot_frame_header; with only literal known magics
// counting (v10 behaviour) the case is lost.
func TestPivotFrameHeaderCorpusMutation(t *testing.T) {
	sc, err := sy.LoadScenario("../../corpus/scenarios/shape-smb-pipe-framed.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		if _, ok := pipeSignal(analyzeScenario(t, sc, cfg), "diagsvc", "pivot_frame_header"); !ok {
			t.Errorf("v2=%v: shape-smb-pipe-framed lost pivot_frame_header", cfg.TimingV2)
		}
		pivotFrames = false
		_, ok := pipeSignal(analyzeScenario(t, sc, cfg), "diagsvc", "pivot_frame_header")
		pivotFrames = true
		if ok {
			t.Errorf("v2=%v: mutation (literal magics only) still fires", cfg.TimingV2)
		}
	}
}

// v11a remediation F05: merging is deterministic and keeps a dominant
// incoming candidate within the 16-entry bound (reviewer probe shape:
// 15 singletons in dst, c0ffee01×300 + one singleton in src).
func TestFrameMergeDeterministic(t *testing.T) {
	build := func() (dst, src frameTrack) {
		for j := 1; j <= 15; j++ {
			dst[0][0].add([4]byte{1, 2, 3, byte(j)})
		}
		for j := 0; j < 300; j++ {
			src[0][0].add([4]byte{0xc0, 0xff, 0xee, 1})
		}
		src[0][0].add([4]byte{9, 8, 7, 6})
		return
	}
	want := [4]byte{0xc0, 0xff, 0xee, 1}
	for k := 0; k < 1000; k++ {
		for _, reverse := range []bool{false, true} {
			dst, src := build()
			if reverse {
				src.merge(&dst)
				dst = src
			} else {
				dst.merge(&src)
			}
			h, ok := dst.constant()
			if !ok || h.value != want || h.hits != 300 || h.msg != 316 {
				t.Fatalf("run %d reverse=%v: %+v ok=%v", k, reverse, h, ok)
			}
			if n := len(dst[0][0].counts); n > framePrefixMaxCands {
				t.Fatalf("table grew to %d", n)
			}
		}
	}
}

// Saturated tables and ties: the kept set is the top 16 by count, ties
// by byte value, whatever the merge order.
func TestFrameMergeTiesAndSaturation(t *testing.T) {
	mk := func(vals []byte, n int) frameTrack {
		var tr frameTrack
		for _, v := range vals {
			for i := 0; i < n; i++ {
				tr[1][1].add([4]byte{0xaa, 0, 0, v})
			}
		}
		return tr
	}
	var a, b []byte
	for v := 0; v < 16; v++ {
		a = append(a, byte(v))
		b = append(b, byte(100+v))
	}
	x, y := mk(a, 2), mk(b, 2) // 32 candidates tied at 2
	x.merge(&y)
	y2, x2 := mk(b, 2), mk(a, 2)
	y2.merge(&x2)
	for _, tr := range []frameTrack{x, y2} {
		if len(tr[1][1].counts) != framePrefixMaxCands || tr[1][1].n != 64 {
			t.Fatalf("bound/n: %d %d", len(tr[1][1].counts), tr[1][1].n)
		}
		for v := 0; v < 16; v++ { // ties keep the smallest values
			if tr[1][1].counts[[4]byte{0xaa, 0, 0, byte(v)}] != 2 {
				t.Fatalf("tie-break kept the wrong candidates: %v", tr[1][1].counts)
			}
		}
	}
	// other directions / offsets are merged independently
	var p, q frameTrack
	q[0][1].add([4]byte{5, 5, 5, 5})
	p.merge(&q)
	if p[0][1].n != 1 || p[0][0].n != 0 || p[1][1].n != 0 {
		t.Errorf("direction/offset leak: %+v", p)
	}
}

// SMB output is stable across repeated runs (both engines).
func TestPivotFrameHeaderStableRuns(t *testing.T) {
	sc, err := sy.LoadScenario("../../corpus/scenarios/shape-smb-pipe-framed.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		var first string
		for k := 0; k < 5; k++ {
			f, _ := pipeSignal(analyzeScenario(t, sc, cfg), "diagsvc", "pivot_frame_header")
			got := fmt.Sprintf("%.4f %v", f.Score, signalNames(f))
			if k == 0 {
				first = got
			} else if got != first {
				t.Fatalf("v2=%v run %d: %s != %s", cfg.TimingV2, k, got, first)
			}
		}
	}
}
