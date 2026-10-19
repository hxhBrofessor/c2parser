package engine

import (
	"fmt"
	mrand "math/rand/v2"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/layers"

	sy "c2parser/internal/synth"
)

// Generic, intentionally non-protocol sweep retained from the original F07
// study. Invented field tags, fixed records, 60-symbol labels and the short
// cached control below are generic positional experiments, not source-grounded
// Sliver evidence. TestSliverDNSFalsification is the separate snapshot study.

type sliverStudy struct {
	model    sy.DNSWireModel
	sessions int
}

func (st sliverStudy) name() string {
	a := "rfc4648"
	if st.model.Alphabet == sy.DNSAlphaCustom32 {
		a = "custom32"
	}
	return fmt.Sprintf("%s/%s/%d-session", a, st.model.Envelope, st.sessions)
}

// leadingColumns computes, from the labels, the number of leading columns
// where every label agrees (exact) and where ≥ 90 % agree (the
// profiler's rule) — the bounds the reported prefix must sit in.
func leadingColumns(labels []string) (exact, ninety int, col0 int) {
	if len(labels) == 0 {
		return
	}
	syms := map[byte]bool{}
	for _, l := range labels {
		if l != "" {
			syms[l[0]] = true
		}
	}
	col0 = len(syms)
	exactOpen := true
	for i := 0; ; i++ {
		c := map[byte]int{}
		n := 0
		for _, l := range labels {
			if i < len(l) {
				c[l[i]]++
				n++
			}
		}
		if n < posMinSamples {
			return
		}
		top := 0
		for _, v := range c {
			top = max(top, v)
		}
		if exactOpen && top == n {
			exact++
		} else {
			exactOpen = false
		}
		if float64(top) < 0.9*float64(n) {
			return
		}
		ninety++
	}
}

func TestGenericDNSWireSweep(t *testing.T) {
	var studies []sliverStudy
	for _, alpha := range []string{sy.DNSAlphaRFC4648, sy.DNSAlphaCustom32} {
		for _, env := range []string{"protobuf", "fixed"} {
			for _, sess := range []int{1, 3} {
				studies = append(studies, sliverStudy{sy.DNSWireModel{Alphabet: alpha, Envelope: env, LabelLen: 60}, sess})
			}
		}
	}
	for i, st := range studies {
		t.Run(st.name(), func(t *testing.T) {
			const zone = "sliverdns.example"
			s := newSynth(t)
			r := mrand.New(mrand.NewPCG(71, uint64(72+i)))
			ts := s.now
			id := uint16(1)
			var firstLabels []string
			seen := map[string]bool{}
			labelLens := map[int]int{}
			for si := 0; si < st.sessions; si++ {
				session := r.Uint32()
				for k := 0; k < 240/st.sessions; k++ {
					ts = ts.Add(time.Duration((4 + (r.Float64()*2 - 1)) * float64(time.Second)))
					msgType := uint32(1) // poll dominates, like a live session
					if r.IntN(6) == 0 {
						msgType = uint32(2 + r.IntN(3))
					}
					ct := make([]byte, 16+r.IntN(220))
					for j := range ct {
						ct[j] = byte(r.IntN(256))
					}
					for _, name := range st.model.Message(r, zone, session, msgType, ct) {
						first := strings.SplitN(name, ".", 2)[0]
						if !seen[name] {
							seen[name] = true
							firstLabels = append(firstLabels, first)
						}
						for _, l := range strings.Split(strings.TrimSuffix(name, "."+zone), ".") {
							labelLens[len(l)]++
						}
						s.dnsQuery(ts, "10.0.0.70", "10.0.0.53", name, layers.DNSTypeA, id)
						s.dnsResp(ts.Add(15*time.Millisecond), "10.0.0.70", "10.0.0.53", name, layers.DNSTypeA, id,
							layers.DNSResponseCodeNoErr, []layers.DNSResourceRecord{{Name: []byte(name), Type: layers.DNSTypeA,
								Class: layers.DNSClassIN, TTL: 0, IP: []byte{byte(r.IntN(255)), byte(r.IntN(255)), 0, 1}}})
						id++
					}
				}
			}
			// Generic short cached control: same alphabet, UNMATCHED length; benign
			// resolution behaviour (a fixed set of hashed-looking names
			// resolved repeatedly with a cacheable TTL)
			confZone := "cdn-confuser.example"
			var confNames []string
			for k := 0; k < 20; k++ {
				b := make([]byte, 9+r.IntN(4))
				for j := range b {
					b[j] = byte(r.IntN(256))
				}
				confNames = append(confNames, st.model.Base32(b)+"."+confZone)
			}
			for k := 0; k < 200; k++ {
				ts = ts.Add(time.Duration((3 + r.Float64()*4) * float64(time.Second)))
				name := confNames[r.IntN(len(confNames))]
				s.dnsQuery(ts, "10.0.0.71", "10.0.0.53", name, layers.DNSTypeA, id)
				s.dnsResp(ts.Add(12*time.Millisecond), "10.0.0.71", "10.0.0.53", name, layers.DNSTypeA, id,
					layers.DNSResponseCodeNoErr, []layers.DNSResourceRecord{{Name: []byte(name), Type: layers.DNSTypeA,
						Class: layers.DNSClassIN, TTL: 300, IP: []byte{192, 0, 2, byte(1 + r.IntN(20))}}})
				id++
			}
			res := s.analyze(Config{})
			var dom *DNSDomainSummary
			for k := range res.DNS {
				if res.DNS[k].Domain == zone {
					dom = &res.DNS[k]
				}
			}
			if dom == nil {
				t.Fatal("modelled zone missing from summaries")
			}
			pos := dom.Positional
			exact, ninety, col0 := leadingColumns(firstLabels[:min(len(firstLabels), maxLabelSample)])
			lens := make([]int, 0, len(labelLens))
			for l := range labelLens {
				lens = append(lens, l)
			}
			sort.Ints(lens)
			f := findBy(res, CatDNS, zone)
			if f == nil {
				t.Fatal("modelled zone not detected")
			}
			// Generic-model measurement only.
			t.Logf("STUDY %-28s prefix=%q (len %d; data: exact %d, ≥90%% %d) col0-symbols=%d constant=%d varying=%d ratio=%.2f pos-score=%.2f remainder=%s/%.2f labels=%v raw-card=%.2f logical-card=%.2f finding=%.2f %s %v",
				st.name(), pos.Prefix, len(pos.Prefix), exact, ninety, col0, pos.Constant, pos.Varying, pos.Ratio, pos.Score,
				pos.Remainder.Alphabet, pos.Remainder.Score, lens, dom.RawCard, dom.Cardinality, f.Score, f.Severity, signalNames(f))
			// --- assertions: no prefix assumption ---
			// the profiler reports what the data contains
			if len(pos.Prefix) < exact || len(pos.Prefix) > ninety {
				t.Errorf("reported prefix %q (len %d) outside the data's leading columns [%d, %d]", pos.Prefix, len(pos.Prefix), exact, ninety)
			}

			// detection never depends on a framing prefix — nor on the
			// positional profile: with a protobuf envelope over several
			// sessions, varint widths move the constant tag bytes between
			// columns, the columns are neither constant nor random and
			// positional_randomness does not fire (a recorded limit of the
			// profiler; the finding stands on cardinality, volume and
			// name shape)
			if !hasSignal(f, "name_cardinality_ratio") || f.Score < 0.65 {
				t.Errorf("detection: %.2f %v", f.Score, signalNames(f))
			}
			if hasSignal(f, "framing_prefix") && pos.Prefix == "" {
				t.Errorf("framing_prefix fired with no prefix")
			}
			if pos.Varying == 0 || pos.Remainder.Score < 0.9 {
				t.Errorf("varying columns not random in aggregate: %+v", pos.Remainder)
			}
			if c := findBy(res, CatDNS, confZone); c != nil && c.Score >= 0.4 {
				t.Errorf("benign confuser zone flagged %.2f: %v", c.Score, signalNames(c))
			}
		})
	}
}

// Snapshot-derived QUERY fixtures only. Ciphertext, interleaving, retries,
// response values and traffic mix are local assumptions, not source claims.
type dnsWireQuery struct {
	msg  sy.SliverDNSFixture
	name string
	qt   layers.DNSType
}

func sourceDNSQueries(t *testing.T, mode string, sessions int) []dnsWireQuery {
	t.Helper()
	r := mrand.New(mrand.NewPCG(701, 702))
	ids := []uint32{1, 0x1234, 0xf01234}
	var queries []dnsWireQuery
	for k := 0; k < 240; k++ {
		sid := ids[k%sessions]
		var nonce [8]byte
		for i := range nonce {
			nonce[i] = byte(r.IntN(256))
		}
		poll, err := sy.SliverDNSPollFixture(sid, nonce)
		if err != nil {
			t.Fatal(err)
		}
		parts := []sy.SliverDNSFixture{poll}
		switch mode {
		case "poll":
		case "mixed":
			mid, err := sy.SliverDNSID(sid, uint8(k%255))
			if err != nil {
				t.Fatal(err)
			}
			switch k % 4 {
			case 0:
				data := make([]byte, 128+256*((k/4)%2))
				for i := range data {
					data[i] = byte(r.IntN(256))
				}
				parts, err = sy.SliverDNSFragments("wire.example", sid, uint8(k%255), data)
				if err != nil {
					t.Fatal(err)
				}
			case 1:
				parts = []sy.SliverDNSFixture{{Type: sy.SliverDNSToImplant, ID: mid, Start: uint32(k % 128), Stop: uint32(k%128 + 64)}}
			case 3:
				parts = []sy.SliverDNSFixture{{Type: sy.SliverDNSClear, ID: mid, Data: nonce[:]}}
			}
		case "no-prefix":
			if k%2 == 0 {
				mid, _ := sy.SliverDNSID(sid, uint8(k%255))
				parts = []sy.SliverDNSFixture{{Type: sy.SliverDNSNOP, ID: mid, Data: nonce[:]}}
			}
		default:
			t.Fatal("unknown fixture mode")
		}
		for _, m := range parts {
			name, err := sy.SliverDNSName("wire.example", m)
			if err != nil {
				t.Fatal(err)
			}
			qt := layers.DNSTypeA
			if m.Type == sy.SliverDNSPoll || m.Type == sy.SliverDNSToImplant {
				qt = layers.DNSTypeTXT
			}
			queries = append(queries, dnsWireQuery{m, name, qt})
		}
	}
	return queries
}
func validateSourceDNSQueries(qs []dnsWireQuery, sessions int) error {
	ids := map[uint32]bool{}
	nonces := map[string]bool{}
	for _, q := range qs {
		ids[q.msg.ID&0xffffff] = true
		if q.msg.ID&0xffffff == 0 {
			return fmt.Errorf("zero session")
		}
		name, err := sy.SliverDNSName("wire.example", q.msg)
		if err != nil || name != q.name {
			return fmt.Errorf("wire correspondence")
		}
		labels := strings.Split(strings.TrimSuffix(q.name, ".wire.example."), ".")
		for i, l := range labels {
			if len(l) > 63 || i < len(labels)-1 && len(l) != 63 {
				return fmt.Errorf("label split")
			}
			for _, c := range l {
				if !strings.ContainsRune(sy.DNSAlphaCustom32, c) {
					return fmt.Errorf("alphabet")
				}
			}
		}
		if q.msg.Type == sy.SliverDNSPoll || q.msg.Type == sy.SliverDNSNOP || q.msg.Type == sy.SliverDNSClear {
			if len(q.msg.Data) != 8 {
				return fmt.Errorf("nonce not in eight Data bytes")
			}
			key := fmt.Sprintf("%d/%d/%x", q.msg.ID&0xffffff, q.msg.Type, q.msg.Data)
			if nonces[key] {
				return fmt.Errorf("nonce reused in fixture")
			}
			nonces[key] = true
		}
	}
	if len(ids) != sessions {
		return fmt.Errorf("got %d sessions, expected %d", len(ids), sessions)
	}
	return nil
}

// Matched controls share EVERY name's label-length pattern, allowed alphabet,
// qtype, query count, retry count and send time. Cacheable controls deliberately
// reuse a finite dictionary of names (two per shape); the novel-hash confuser
// instead has the same high cardinality as the query model. Neither is C2.
func sourceDNSCapture(t *testing.T, qs []dnsWireQuery, cfg Config) *Result {
	t.Helper()
	s := newSynth(t)
	r := mrand.New(mrand.NewPCG(703, 704))
	cache := map[string][]string{}
	visits := map[string]int{}
	// Each cached pair covers the full allowed alphabet even for short polls.
	// A shuffled 32-symbol cycle is local synthetic data, not protocol framing.
	cycle := []byte(sy.DNSAlphaCustom32)
	r.Shuffle(len(cycle), func(i, j int) { cycle[i], cycle[j] = cycle[j], cycle[i] })
	cycleAt := 0
	support := [3]map[byte]bool{{}, {}, {}}
	id := uint16(1)
	for k, q := range qs {
		sub := strings.TrimSuffix(q.name, ".wire.example.")
		labels := strings.Split(sub, ".")
		var shape []string
		for _, l := range labels {
			shape = append(shape, fmt.Sprint(len(l)))
		}
		shapeKey := strings.Join(shape, "/")
		randomSub := func() string {
			var out []string
			for _, l := range labels {
				b := make([]byte, len(l))
				for j := range b {
					b[j] = sy.DNSAlphaCustom32[r.IntN(32)]
				}
				out = append(out, string(b))
			}
			return strings.Join(out, ".")
		}
		if cache[shapeKey] == nil {
			for pair := 0; pair < 2; pair++ {
				var out []string
				for _, l := range labels {
					b := make([]byte, len(l))
					for j := range b {
						b[j] = cycle[cycleAt%32]
						cycleAt++
					}
					out = append(out, string(b))
				}
				cache[shapeKey] = append(cache[shapeKey], strings.Join(out, "."))
			}
		}
		cached := cache[shapeKey][visits[shapeKey]%2]
		visits[shapeKey]++
		names := []string{q.name, cached + ".safe.example.", randomSub() + ".hash.example."}
		for group, name := range names {
			// Assert exact per-query shape matching, rather than only an average.
			if got := strings.Split(strings.TrimSuffix(name, "."), "."); len(got) != len(labels)+2 {
				t.Fatal("control label count")
			}
			for i, l := range strings.Split(name, ".")[:len(labels)] {
				if len(l) != len(labels[i]) {
					t.Fatal("control label length")
				}
				for _, c := range []byte(l) {
					if !strings.ContainsRune(sy.DNSAlphaCustom32, rune(c)) {
						t.Fatal("control encoding alphabet")
					}
					support[group][c] = true
				}
			}
			// Builder accepts presentation names without the root dot; the DNS
			// serializer supplies the terminating zero label on the wire.
			name = strings.TrimSuffix(name, ".")
			client := fmt.Sprintf("10.0.0.%d", 70+group)
			for retry := 0; retry < 3; retry++ {
				ts := s.now.Add(time.Duration(k)*6*time.Second + time.Duration(retry)*100*time.Millisecond)
				s.dnsQuery(ts, client, "10.0.0.53", name, q.qt, id)
				ttl := uint32(300)
				if group == 0 {
					ttl = 0
				}
				rr := layers.DNSResourceRecord{Name: []byte(name), Type: q.qt, Class: layers.DNSClassIN, TTL: ttl}
				if q.qt == layers.DNSTypeTXT {
					rr.TXTs = [][]byte{[]byte("ok")}
				} else {
					rr.IP = []byte{192, 0, 2, 1}
				}
				s.dnsResp(ts.Add(15*time.Millisecond), client, "10.0.0.53", name, q.qt, id, layers.DNSResponseCodeNoErr, []layers.DNSResourceRecord{rr})
				id++
			}
		}
	}
	for _, symbols := range support {
		if len(symbols) != 32 {
			t.Fatal("control observed symbol support not matched")
		}
	}
	return s.analyze(cfg)
}
func studyDomain(t *testing.T, res *Result, zone string) *DNSDomainSummary {
	t.Helper()
	for i := range res.DNS {
		if res.DNS[i].Domain == zone {
			return &res.DNS[i]
		}
	}
	t.Fatal("missing study domain", zone)
	return nil
}
func TestSliverDNSFalsification(t *testing.T) {
	for _, mode := range []string{"poll", "mixed", "no-prefix"} {
		for _, sessions := range []int{1, 3} {
			t.Run(fmt.Sprintf("%s/%d-session", mode, sessions), func(t *testing.T) {
				qs := sourceDNSQueries(t, mode, sessions)
				if err := validateSourceDNSQueries(qs, sessions); err != nil {
					t.Fatal(err)
				}
				// Byte-for-byte deterministic generation and no literal-prefix planting.
				again := sourceDNSQueries(t, mode, sessions)
				if fmt.Sprint(qs) != fmt.Sprint(again) {
					t.Fatal("nondeterministic fixtures")
				}
				var first []string
				seen := map[string]bool{}
				lens := map[int]int{}
				for _, q := range qs {
					if !seen[q.name] {
						first = append(first, strings.Split(q.name, ".")[0])
						seen[q.name] = true
					}
					for _, l := range strings.Split(strings.TrimSuffix(q.name, ".wire.example."), ".") {
						lens[len(l)]++
					}
				}
				for _, cfg := range []Config{{}, {TimingV2: true}} {
					res := sourceDNSCapture(t, qs, cfg)
					dom := studyDomain(t, res, "wire.example")
					benign := studyDomain(t, res, "safe.example")
					hard := studyDomain(t, res, "hash.example")
					f := findBy(res, CatDNS, "wire.example")
					if f == nil || f.Score < 0.65 {
						t.Fatal("source query shape not detected")
					}
					exact, ninety, col0 := leadingColumns(first[:min(len(first), maxLabelSample)])
					if len(dom.Positional.Prefix) < exact || len(dom.Positional.Prefix) > ninety {
						t.Fatal("prefix not justified by observed columns")
					}
					if mode == "no-prefix" && (dom.Positional.Prefix != "" || hasSignal(f, "framing_prefix")) {
						t.Fatal("mixed NOP/POLL has no leading constant column")
					}
					for _, c := range []*DNSDomainSummary{benign, hard} {
						if c.Queries != dom.Queries || c.Logical != dom.Logical || c.Retries != dom.Retries || c.MaxLabel != dom.MaxLabel || fmt.Sprint(c.QTypes) != fmt.Sprint(dom.QTypes) {
							t.Fatalf("control counts/qtypes/max-label not matched: %s", c.Domain)
						}
					}
					if res.Counters.DecodeErrors != 0 || res.Counters.DNSDecodeErrors != 0 {
						t.Fatal("capture decoding error")
					}
					if dom.Responses != dom.Queries || benign.Responses != benign.Queries || hard.Responses != hard.Queries {
						t.Fatal("DNS response count differs")
					}
					if dom.Queries != 3*len(qs) || dom.Retries != 2*len(qs) {
						t.Fatal("retries/counts differ")
					}
					bf := findBy(res, CatDNS, "safe.example")
					bs := 0.0
					if bf != nil {
						bs = bf.Score
					}
					if bs >= 0.4 {
						for _, signal := range bf.Signals {
							t.Logf("CACHED_NEGATIVE mode=%s sessions=%d v2=%v signal=%s score=%.2f weight=%.2f contribution=%.3f", mode, sessions, cfg.TimingV2, signal.Name, signal.Score, signal.Weight, signal.Contribution())
						}
						t.Errorf("cached matched benign control exceeds existing low bound: %.2f", bs)
					}
					hf := findBy(res, CatDNS, "hash.example")
					hs := 0.0
					if hf != nil {
						hs = hf.Score
					}
					// A deliberately hard benign confuser may flag: report the limitation,
					// never change scoring or claim that passive structure proves attribution.
					t.Logf("SOURCE mode=%s sessions=%d v2=%v names=%d queries=%d retries=%d labels=%v col0=%d prefix=%q constants=%d varying=%d pos=%.3f remainder=%s/%.3f raw-card=%.3f logical-card=%.3f score=%.2f %s cached-benign=%.2f novel-benign=%.2f signals=%v", mode, sessions, cfg.TimingV2, len(qs), dom.Queries, dom.Retries, lens, col0, dom.Positional.Prefix, dom.Positional.Constant, dom.Positional.Varying, dom.Positional.Score, dom.Positional.Remainder.Alphabet, dom.Positional.Remainder.Score, dom.RawCard, dom.Cardinality, f.Score, f.Severity, bs, hs, signalNames(f))
				}
			})
		}
	}
}
func TestSliverDNSStudyMutations(t *testing.T) {
	for _, sessions := range []int{1, 3} {
		qs := sourceDNSQueries(t, "poll", sessions)
		if err := validateSourceDNSQueries(qs, sessions); err != nil {
			t.Fatal(err)
		}
		for i := range qs {
			if sessions == 3 {
				qs[i].msg.ID = 1
			} else if i == len(qs)-1 {
				qs[i].msg.ID = 2
			}
			qs[i].name, _ = sy.SliverDNSName("wire.example", qs[i].msg)
		}
		if validateSourceDNSQueries(qs, sessions) == nil {
			t.Fatal("session collapse/introduction mutation escaped oracle")
		}
		qs = sourceDNSQueries(t, "poll", sessions)
		for i := range qs {
			qs[i].msg.Data = make([]byte, 8)
			qs[i].name, _ = sy.SliverDNSName("wire.example", qs[i].msg)
		}
		if validateSourceDNSQueries(qs, sessions) == nil {
			t.Fatal("constant nonce mutation escaped oracle")
		}
		t.Logf("sessions=%d: session-count and nonce mutations rejected", sessions)
	}
}
