package engine

import (
	"encoding/base32"
	"fmt"
	mrand "math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	sy "c2parser/internal/synth"
)

func clientHello(sni string, alpn []string) []byte { return sy.ClientHello(sni, alpn) }

func appData(n int) []byte { return sy.AppData(randB(n)) }

// DoT C2 per the ACM lab: 5 s ± 2 s beacons, one TLS connection per check-in.
func TestDoTBeaconAndIOC(t *testing.T) {
	s := newSynth(t)
	r := mrand.New(mrand.NewPCG(11, 12))
	ts := s.now
	for i := 0; i < 60; i++ {
		ts = ts.Add(time.Duration((5 + 2*(r.Float64()*2-1)) * float64(time.Second)))
		c := s.tcp(ts, "10.0.0.20", uint16(40000+i), "203.0.113.9", 853)
		x := c.Send(ts.Add(3*time.Millisecond), true, clientHello("timeserversync.example", []string{"dot"}), 1400)
		x = c.Send(x.Add(20*time.Millisecond), false, appData(1200), 1400)
		x = c.Send(x.Add(10*time.Millisecond), true, appData(120), 1400)
		c.Close(x.Add(30 * time.Millisecond))
	}
	res := s.analyze(Config{IOCs: []IOC{{Kind: "domain", Value: "timeserversync.example", Label: "lab DoT C2"}}})
	f := findBy(res, CatEncDNS, "203.0.113.9:853")
	if f == nil || f.Score < 0.85 || !hasSignal(f, "dot_port") || !hasSignal(f, "alpn_encrypted_dns") || !hasSignal(f, "beacon_timing") {
		t.Fatalf("DoT not detected: %+v", f)
	}
	c2 := findBy(res, CatC2, "203.0.113.9")
	if c2 == nil || !hasSignal(c2, "ioc:domain") {
		t.Errorf("SNI IOC not matched: %+v", c2)
	}
	var sum *ChannelSummary
	for i := range res.TopTalkers {
		if res.TopTalkers[i].Port == 853 {
			sum = &res.TopTalkers[i]
		}
	}
	if sum == nil || sum.SNI != "timeserversync.example" || !strings.HasPrefix(sum.JA4, "t13d0205dt_") {
		t.Errorf("TLS summary: %+v", sum)
	}
}

// Custom DoH C2 from the ACM lab: one TLS session to a raw IP (no SNI)
// held open for hours with small periodic exchanges. Beacon analysis on
// connection starts sees nothing; the session itself is the anomaly.
func TestDoHRawIPLongSession(t *testing.T) {
	s := newSynth(t)
	r := mrand.New(mrand.NewPCG(13, 14))
	ts := s.now
	c := s.tcp(ts, "10.0.0.21", 41000, "198.51.100.7", 443)
	ts = c.Send(ts.Add(5*time.Millisecond), true, clientHello("", []string{"h2"}), 1400)
	ts = c.Send(ts.Add(30*time.Millisecond), false, appData(2500), 1400)
	for i := 0; i < 1500; i++ { // ~2.5 h at 5 s ± 2 s... plus a long tail below
		ts = ts.Add(time.Duration((6 + 2*(r.Float64()*2-1)) * float64(time.Second)))
		ts = c.Send(ts, true, appData(180), 1400)
		ts = c.Send(ts.Add(25*time.Millisecond), false, appData(90), 1400)
	}
	c.Close(ts.Add(time.Second))
	for _, cfg := range []Config{{}, {TimingV2: true}} {
		res := s.analyze(cfg)
		f := findBy(res, CatC2, "198.51.100.7")
		if f == nil || f.Score < 0.65 || !hasSignal(f, "long_connection") || !hasSignal(f, "tls_no_sni") || !hasTimingSignal(f) {
			t.Fatalf("v2=%v: DoH raw-IP session not detected: %+v", cfg.TimingV2, f)
		}
	}
}

// Sliver-style DNS C2 (Luise 2024): names are built to look ordinary, so
// per-name entropy is unremarkable, but almost every query is a new name.
func TestLowEntropyDNSBeaconCardinality(t *testing.T) {
	s := newSynth(t)
	r := mrand.New(mrand.NewPCG(15, 16))
	syll := strings.Fields("ka re to mi sa no lu be di fo ga he ji ko pa ri su te vo wa ya ze")
	ts := s.now
	id := uint16(1)
	for i := 0; i < 220; i++ {
		ts = ts.Add(time.Duration((3 + 0.5*(r.Float64()*2-1)) * float64(time.Second)))
		var w strings.Builder
		for j := 0; j < 5+r.IntN(4); j++ {
			w.WriteString(syll[r.IntN(len(syll))])
		}
		name := fmt.Sprintf("%s.cdn-sync.example", w.String())
		s.dnsQuery(ts, "10.0.0.30", "10.0.0.53", name, layers.DNSTypeA, id)
		s.dnsResp(ts.Add(20*time.Millisecond), "10.0.0.30", "10.0.0.53", name, layers.DNSTypeA, id, layers.DNSResponseCodeNoErr,
			[]layers.DNSResourceRecord{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 0, IP: []byte{10, byte(r.IntN(255)), byte(r.IntN(255)), 1}}})
		id++
	}
	res := s.analyze(Config{})
	f := findBy(res, CatDNS, "cdn-sync.example")
	if f == nil || f.Score < 0.65 || !hasSignal(f, "name_cardinality_ratio") || !hasSignal(f, "resolved_never_contacted") {
		t.Fatalf("low-entropy DNS beacon not detected: %+v", f)
	}
	for _, d := range res.DNS {
		if d.Domain == "cdn-sync.example" && d.Randomness > 0.5 {
			t.Errorf("test premise broken: names should not look random (%.2f)", d.Randomness)
		}
	}
}

func TestDoQPort(t *testing.T) {
	s := newSynth(t)
	ts := s.now
	for i := 0; i < 30; i++ {
		ts = ts.Add(5 * time.Second)
		init := append([]byte{0xc3, 0, 0, 0, 1, 8}, randB(1200)...) // QUIC v1 long header
		s.udp(ts, "10.0.0.40", 50999, "203.0.113.77", 853, gopacket.Payload(init))
		s.udp(ts.Add(30*time.Millisecond), "203.0.113.77", 853, "10.0.0.40", 50999, gopacket.Payload(append([]byte{0xc3, 0, 0, 0, 1}, randB(600)...)))
	}
	res := s.analyze(Config{})
	f := findBy(res, CatEncDNS, "203.0.113.77:853/udp")
	if f == nil || !hasSignal(f, "doq_port") || !strings.Contains(fmt.Sprint(f.Signals), "QUIC") {
		t.Fatalf("DoQ not detected: %+v", f)
	}
}

func TestParseIOCLine(t *testing.T) {
	cases := map[string]IOC{
		"100.113.27.34":                        {Kind: "ip", Value: "100.113.27.34"},
		"Evil.Example.  # havoc":               {Kind: "domain", Value: "evil.example", Label: "havoc"},
		"ja3:ABCDEF0123456789abcdef0123456789": {Kind: "ja3", Value: "abcdef0123456789abcdef0123456789"},
		"t13d1516h2_8daaf6152771_02713d6af862": {Kind: "ja4", Value: "t13d1516h2_8daaf6152771_02713d6af862"},
		"sni:c2.example":                       {Kind: "domain", Value: "c2.example"},
	}
	for in, want := range cases {
		got, ok := ParseIOCLine(in)
		if !ok || got.Kind != want.Kind || got.Value != want.Value || want.Label != "" && got.Label != want.Label {
			t.Errorf("%q → %+v", in, got)
		}
	}
	if _, ok := ParseIOCLine("   # just a comment"); ok {
		t.Error("comment-only line parsed")
	}
}

// Reproduces the Sliver DNS C2 traffic in Luise (2024): 12-char labels with
// a constant "baak" framing prefix over Sliver's 32-symbol alphabet, each
// name queried 3× (so the naive unique/total ratio is ~0.33), and
// per-name entropy indistinguishable from mozilla.com / gstatic.com.
func TestSliverDNSAsInLuise(t *testing.T) {
	s := newSynth(t)
	r := mrand.New(mrand.NewPCG(31, 32))
	const alpha = "ab1c2d3e4f5g6h7j8k9m0npqrtuvwxyz"
	ts := s.now
	id := uint16(1)
	for i := 0; i < 300; i++ {
		ts = ts.Add(time.Duration((2 + 0.4*(r.Float64()*2-1)) * float64(time.Second)))
		lbl := []byte("baak")
		for j := 0; j < 8; j++ {
			lbl = append(lbl, alpha[r.IntN(len(alpha))])
		}
		name := string(lbl) + ".dns.happytoseeyou.com"
		for rep := 0; rep < 3; rep++ {
			at := ts.Add(time.Duration(rep*150) * time.Millisecond)
			s.dnsQuery(at, "10.0.0.50", "10.0.0.53", name, layers.DNSTypeA, id)
			s.dnsResp(at.Add(15*time.Millisecond), "10.0.0.50", "10.0.0.53", name, layers.DNSTypeA, id, layers.DNSResponseCodeNoErr,
				[]layers.DNSResourceRecord{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 0, IP: []byte{byte(r.IntN(255)), byte(r.IntN(255)), 0, 1}}})
			id++
		}
	}
	for i, n := range []string{"push.services.mozilla.com", "location.services.mozilla.com", "www.gstatic.com", "fonts.gstatic.com", "content-signature-2.cdn.mozilla.net"} {
		for k := 0; k < 30; k++ {
			at := s.now.Add(time.Duration(i*1000+k*37) * time.Second)
			s.dnsQuery(at, "10.0.0.51", "10.0.0.53", n, layers.DNSTypeA, id)
			s.dnsResp(at.Add(10*time.Millisecond), "10.0.0.51", "10.0.0.53", n, layers.DNSTypeA, id, layers.DNSResponseCodeNoErr,
				[]layers.DNSResourceRecord{{Name: []byte(n), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 300, IP: []byte{142, 250, 0, byte(i)}}})
			id++
		}
	}
	res := s.analyze(Config{})
	var sliver, mozilla *DNSDomainSummary
	for i := range res.DNS {
		switch res.DNS[i].Domain {
		case "happytoseeyou.com":
			sliver = &res.DNS[i]
		case "mozilla.com":
			mozilla = &res.DNS[i]
		}
	}
	if sliver == nil || mozilla == nil {
		t.Fatal("domains missing")
	}
	t.Logf("Luise per-name entropy: sliver mean %.2f max %.2f | mozilla mean %.2f", sliver.LuiseMean, sliver.LuiseMax, mozilla.LuiseMean)
	t.Logf("cardinality raw %.2f → logical %.2f; positional %+v", sliver.RawCard, sliver.Cardinality, sliver.Positional)
	// The paper's observation holds: per-name entropy can't separate them.
	if sliver.LuiseMean > mozilla.LuiseMean+0.6 {
		t.Errorf("premise: Sliver per-name entropy %.2f should look like mozilla %.2f", sliver.LuiseMean, mozilla.LuiseMean)
	}
	if sliver.RawCard > 0.4 || sliver.Cardinality < 0.95 {
		t.Errorf("retry de-dup: raw %.2f (want ≈0.33), logical %.2f (want ≈1)", sliver.RawCard, sliver.Cardinality)
	}
	if sliver.Positional.Prefix != "baak" || sliver.Positional.Score < 0.8 || sliver.Positional.Remainder.Alphabet != "custom32" {
		t.Errorf("positional: %+v", sliver.Positional)
	}
	f := findBy(res, CatDNS, "happytoseeyou.com")
	if f == nil || f.Score < 0.85 || !hasSignal(f, "framing_prefix") || !hasSignal(f, "name_cardinality_ratio") {
		t.Fatalf("Sliver DNS not critical: %+v", f)
	}
	if m := findBy(res, CatDNS, "mozilla.com"); m != nil && m.Score >= 0.2 {
		t.Errorf("mozilla flagged %.2f", m.Score)
	}
}

// Mythic "dns" profile: base32 (RFC 4648, no padding) protobuf packets in
// ≤63-char labels, data returned in multiple A records with TTL 0.
func TestMythicDNSProfile(t *testing.T) {
	s := newSynth(t)
	r := mrand.New(mrand.NewPCG(41, 42))
	ts := s.now
	id := uint16(1)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	for i := 0; i < 150; i++ {
		ts = ts.Add(time.Duration((10 * (1 + 0.23*(r.Float64()*2-1))) * float64(time.Second)))
		sub := strings.ToLower(enc.EncodeToString(randB(30 + r.IntN(40))))
		var labels []string
		for len(sub) > 63 {
			labels, sub = append(labels, sub[:63]), sub[63:]
		}
		name := strings.Join(append(labels, sub), ".") + ".ns1.mythic-c2.example"
		var ans []layers.DNSResourceRecord
		for k := 0; k < 6; k++ {
			ans = append(ans, layers.DNSResourceRecord{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 0, IP: append([]byte{byte(k)}, randB(3)...)})
		}
		s.dnsQuery(ts, "10.0.0.60", "10.0.0.53", name, layers.DNSTypeA, id)
		s.dnsResp(ts.Add(25*time.Millisecond), "10.0.0.60", "10.0.0.53", name, layers.DNSTypeA, id, layers.DNSResponseCodeNoErr, ans)
		id++
	}
	res := s.analyze(Config{})
	f := findBy(res, CatDNS, "mythic-c2.example")
	if f == nil || f.Score < 0.85 {
		t.Fatalf("Mythic DNS not critical: %+v", f)
	}
	for _, n := range []string{"ttl_zero_answers", "data_in_address_answers", "resolved_never_contacted", "beacon_timing"} {
		if !hasSignal(f, n) {
			t.Errorf("missing %s: %+v", n, f.Signals)
		}
	}
}

// hasTimingSignal accepts the v1 (beacon_timing) or v2 (timing_dispersion)
// timing signal.
func hasTimingSignal(f *Finding) bool {
	return hasSignal(f, "beacon_timing") || hasSignal(f, "timing_dispersion")
}
