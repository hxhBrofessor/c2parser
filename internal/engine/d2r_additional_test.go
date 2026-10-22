package engine

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

// smbPipeConnNoFinD2R emits the same minimal SMB named-pipe exchange as
// smbPipeConn but deliberately omits FIN/RST, for the bounded R1-08 case.
func smbPipeConnNoFinD2R(s *synth, client string, cport uint16, server, pipeName string, start time.Time, payloads ...[]byte) {
	smbPipeConnNoFinWithISND2R(s, client, cport, server, pipeName, start, 1000, 9000, payloads...)
}

func smbPipeConnNoFinWithISND2R(s *synth, client string, cport uint16, server, pipeName string, start time.Time, clientISN, serverISN uint32, payloads ...[]byte) {
	ts := start
	sess := s.b.TCPWithISN(ts, client, cport, server, 445, clientISN, serverISN)
	step := func(d time.Duration, fromClient bool, msg []byte) {
		ts = ts.Add(d)
		sess.Send(ts, fromClient, nb(msg), 1400)
	}
	const tree = 5
	fid := bytes.Repeat([]byte{0xcd}, 16)
	path := u16le(`\\` + server + `\IPC$`)
	tc := make([]byte, 8)
	binary.LittleEndian.PutUint16(tc[0:], 9)
	binary.LittleEndian.PutUint16(tc[4:], 64+8)
	binary.LittleEndian.PutUint16(tc[6:], uint16(len(path)))
	step(time.Millisecond, true, append(append(smb2Hdr(smbCmdTreeConnect, false, 1, 0, 0), tc...), path...))
	step(time.Millisecond, false, append(smb2Hdr(smbCmdTreeConnect, true, 1, tree, 0), make([]byte, 16)...))
	name := u16le(pipeName)
	cr := make([]byte, 56)
	binary.LittleEndian.PutUint16(cr[0:], 57)
	binary.LittleEndian.PutUint16(cr[44:], 64+56)
	binary.LittleEndian.PutUint16(cr[46:], uint16(len(name)))
	step(time.Millisecond, true, append(append(smb2Hdr(smbCmdCreate, false, 2, tree, 0), cr...), name...))
	crr := make([]byte, 88)
	binary.LittleEndian.PutUint16(crr[0:], 89)
	binary.LittleEndian.PutUint32(crr[4:], 1)
	copy(crr[64:80], fid)
	step(time.Millisecond, false, append(smb2Hdr(smbCmdCreate, true, 2, tree, 0), crr...))
	for i, data := range payloads {
		wr := make([]byte, 48)
		binary.LittleEndian.PutUint16(wr[0:], 49)
		binary.LittleEndian.PutUint16(wr[2:], 64+48)
		binary.LittleEndian.PutUint32(wr[4:], uint32(len(data)))
		copy(wr[16:32], fid)
		step(10*time.Second, true, append(append(smb2Hdr(smbCmdWrite, false, uint64(3+i), tree, 0), wr...), data...))
	}
}

// RV-1: R1-08 characterization, not a uniqueness test. A FIN-less 4-tuple
// reused after a gap gets no second SMB observation today (R1-08: the
// reassembly stream stays on the first connection), so the counts below pin
// current behavior: 1 smb_pipe series and 1 pipe finding. When FIX-REUSE
// lands, this must become a uniqueness test (2 series, 2 distinct keys,
// still 1 pipe finding) and these assertions must change with it.
func TestR108FINlessReuseCharacterization(t *testing.T) {
	for _, tc := range []struct {
		name string
		isn  uint32
	}{{"same-ISN", 1000}, {"new-ISN-above-high-water", 100000}} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSynth(t)
			payloads := make([][]byte, 8)
			for i := range payloads {
				payloads[i] = bytes.Repeat([]byte{byte(i + 1)}, 64)
			}
			smbPipeConnNoFinWithISND2R(s, "10.7.0.5", 50001, "10.7.0.11", "reuse_pipe", s.now, 1000, 9000, payloads...)
			smbPipeConnNoFinWithISND2R(s, "10.7.0.5", 50001, "10.7.0.11", "reuse_pipe", s.now.Add(5*time.Minute), tc.isn, tc.isn+8000, payloads...)
			res := s.analyze(Config{TimingV2: true, RecordConns: true})
			ss := pipeSeries(res)
			if len(res.Conns) != 2 || len(ss) != 2 || distinctKeys(ss) != 2 {
				t.Fatalf("TCP connections=%d, smb_pipe series=%d distinct keys=%d, want 2/2/2", len(res.Conns), len(ss), distinctKeys(ss))
			}
			pipes := 0
			for _, f := range res.Findings {
				if f.Category == CatPipe {
					pipes++
				}
			}
			if pipes != 1 {
				t.Fatalf("pipe findings=%d, want 1 under address-only finding aggregation", pipes)
			}
		})
	}
}

func TestD2R09TimingContentEqualModuloKey(t *testing.T) {
	s := newSynth(t)
	payloads := make([][]byte, 8)
	for i := range payloads {
		payloads[i] = bytes.Repeat([]byte{byte(i + 1)}, 64)
	}
	smbPipeConn(s, "10.7.0.5", 50001, "10.7.0.11", "reuse_pipe", s.now, payloads...)
	smbPipeConn(s, "10.7.0.5", 50001, "10.7.0.11", "reuse_pipe", s.now.Add(5*time.Minute), payloads...)
	_, results := analyzeRuns(t, s, Config{TimingV2: true}, 10)
	var baseline []byte
	var times0 [][]float64
	for run, res := range results {
		ss := pipeSeries(res)
		if len(ss) != 2 || distinctKeys(ss) != 2 {
			t.Fatalf("run %d: series=%d distinct keys=%d, want 2/2", run, len(ss), distinctKeys(ss))
		}
		// RV-2: times are unexported, so the JSON below does not cover
		// them. Compare the event times exactly, in integer nanoseconds:
		// the second connection's events are the first's plus the 5 min
		// start offset, and each series repeats bit for bit across runs.
		t0, t1 := ss[0].Times(), ss[1].Times()
		if len(t0) == 0 || len(t0) != len(t1) {
			t.Fatalf("run %d: event counts %d vs %d", run, len(t0), len(t1))
		}
		for i := range t0 {
			if d := math.Round(t1[i]*1e9) - math.Round(t0[i]*1e9); d != float64(5*time.Minute) {
				t.Fatalf("run %d: event %d at %v vs %v, want an offset of exactly 5m", run, i, t0[i], t1[i])
			}
		}
		if run == 0 {
			times0 = [][]float64{t0, t1}
		} else if !reflect.DeepEqual([][]float64{t0, t1}, times0) {
			t.Fatalf("run %d: event times differ from run 0", run)
		}
		var content [][]byte
		for _, series := range ss {
			series.Key = ""
			b, err := json.Marshal(series)
			if err != nil {
				t.Fatal(err)
			}
			content = append(content, b)
		}
		if !bytes.Equal(content[0], content[1]) {
			t.Fatalf("run %d: timing content differs beyond the key:\n%s\n%s", run, content[0], content[1])
		}
		joined, _ := json.Marshal(content)
		if run == 0 {
			baseline = joined
		} else if !bytes.Equal(joined, baseline) {
			t.Fatalf("run %d: normalized timing content differs from run 0", run)
		}
	}
}

func TestD2R10FindingScoreSeverityEvidenceUnchanged(t *testing.T) {
	payloads := make([][]byte, 8)
	for i := range payloads {
		payloads[i] = bytes.Repeat([]byte{byte(i + 1)}, 64)
	}
	one := newSynth(t)
	smbPipeConn(one, "10.7.0.5", 50001, "10.7.0.11", "reuse_pipe", one.now, payloads...)
	oneResult := one.analyze(Config{TimingV2: true})

	two := newSynth(t)
	smbPipeConn(two, "10.7.0.5", 50001, "10.7.0.11", "reuse_pipe", two.now, payloads...)
	smbPipeConn(two, "10.7.0.5", 50001, "10.7.0.11", "reuse_pipe", two.now.Add(5*time.Minute), payloads...)
	twoResult := two.analyze(Config{TimingV2: true})
	var f1, f2 *Finding
	for i := range oneResult.Findings {
		if oneResult.Findings[i].Category == CatPipe {
			f1 = &oneResult.Findings[i]
		}
	}
	for i := range twoResult.Findings {
		if twoResult.Findings[i].Category == CatPipe {
			if f2 != nil {
				t.Fatal("multiple pipe findings; address-only finding identity changed")
			}
			f2 = &twoResult.Findings[i]
		}
	}
	if f1 == nil || f2 == nil {
		t.Fatalf("pipe finding missing: single=%v repeated=%v", f1 != nil, f2 != nil)
	}
	if f1.Score != f2.Score || f1.Severity != f2.Severity || !reflect.DeepEqual(f1.Evidence, f2.Evidence) {
		t.Fatalf("finding changed: single score/severity/evidence=%v/%q/%q repeated=%v/%q/%q", f1.Score, f1.Severity, f1.Evidence, f2.Score, f2.Severity, f2.Evidence)
	}
}

func TestIPv6DNSTieOrder(t *testing.T) {
	low := netip.MustParseAddr("fd00::5")
	high := netip.MustParseAddr("fd00::11")
	for run := 0; run < 10; run++ {
		addrs := []netip.Addr{low, high}
		if run%2 == 1 {
			addrs[0], addrs[1] = addrs[1], addrs[0]
		}
		e := New(Config{})
		e.first = time.Unix(100, 0).UTC()
		e.last = e.first.Add(10 * time.Minute)
		e.dns = newDNSState()
		subs := make(map[string]struct{}, 20)
		labels := make([]string, 0, 20)
		for i := 0; i < 20; i++ {
			label := fmt.Sprintf("sample%02d", i)
			subs[label+".tie.example"] = struct{}{}
			labels = append(labels, label)
		}
		times := make([]float64, 20)
		sizes := make([]float64, 20)
		for i := range times {
			times[i] = float64(i) * 30
			sizes[i] = 80
		}
		clients := make(map[netip.Addr]*dnsSeries, 2)
		for _, addr := range addrs {
			clients[addr] = &dnsSeries{t: append([]float64(nil), times...), size: append([]float64(nil), sizes...)}
		}
		e.dns.domains["tie.example"] = &dnsDomain{
			base: "tie.example", queries: 20, logical: 20, qtypes: map[string]int{"A": 20},
			subs: subs, subChars: 180, maxLabel: 9, clients: clients, labels: labels,
			first: e.first, last: e.last,
		}
		sc := &scorer{accs: make(map[string]*acc)}
		e.scoreDNS(sc)
		a := sc.accs["dns|tie.example"]
		if a == nil {
			t.Fatal("DNS tie finding missing")
		}
		if want := fmt.Sprintf("client %s)", low); !strings.Contains(a.f.Title, want) {
			t.Fatalf("run %d: title %q, want lower IPv6 client %s", run, a.f.Title, low)
		}
	}
}
