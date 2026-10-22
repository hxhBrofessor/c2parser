package engine

import (
	"c2parser/internal/stats"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestPM4RX11FirstInvalidSNIIsLexical(t *testing.T) {
	cert := &x509.Certificate{DNSNames: []string{"valid.example"}}
	for i := 0; i < 64; i++ {
		m := map[string]int{"z.invalid": 1, "a.invalid": 1}
		if got := firstInvalidSNI(m, cert); got != "a.invalid" {
			t.Fatalf("selected %q, want lexical first a.invalid", got)
		}
	}
}

func TestPM4RHTTPSummaryTieUsesIdentity(t *testing.T) {
	a := &httpChannel{key: httpChanKey{client: netip.MustParseAddr("10.0.0.1"), server: netip.MustParseAddr("10.0.0.2"), port: 80, host: "a.example"}, requests: 1}
	b := &httpChannel{key: httpChanKey{client: netip.MustParseAddr("10.0.0.3"), server: netip.MustParseAddr("10.0.0.4"), port: 80, host: "b.example"}, requests: 1}
	for _, order := range [][]*httpChannel{{a, b}, {b, a}} {
		e := New(Config{MaxSummaryRows: 1})
		e.httpOrder = order
		got := e.httpSummaries()
		if len(got) != 1 || got[0].Host != "a.example" {
			t.Fatalf("HTTP tie chose %#v", got)
		}
	}
}

func TestPM4RSMBSummaryTieUsesIdentity(t *testing.T) {
	rows := []SMBFileSummary{{Client: "10.0.0.2", Server: "10.0.0.3", Name: "z", WriteBytes: 5}, {Client: "10.0.0.1", Server: "10.0.0.3", Name: "a", WriteBytes: 5}}
	for _, input := range [][]SMBFileSummary{{rows[0], rows[1]}, {rows[1], rows[0]}} {
		got := append([]SMBFileSummary(nil), input...)
		sortSMBSummaries(got)
		if got[0].Name != "a" {
			t.Fatalf("SMB tie chose %#v", got)
		}
	}
}

func TestPM4RTopTalkerTieUsesIdentity(t *testing.T) {
	a := &channel{key: chanKey{client: netip.MustParseAddr("10.0.0.1"), server: netip.MustParseAddr("10.0.0.2"), port: 80, proto: "tcp"}, out: 10}
	b := &channel{key: chanKey{client: netip.MustParseAddr("10.0.0.3"), server: netip.MustParseAddr("10.0.0.4"), port: 80, proto: "tcp"}, out: 10}
	for _, order := range [][]*channel{{a, b}, {b, a}} {
		e := New(Config{})
		e.chOrder = order
		got := e.topTalkers(1)
		if len(got) != 1 || got[0].Client != "10.0.0.1" {
			t.Fatalf("talker tie chose %#v", got)
		}
	}
}

func TestPM4RUDPFlushTieUsesSortedFlowKey(t *testing.T) {
	k1 := mkKey(netip.MustParseAddrPort("10.0.0.1:1000"), netip.MustParseAddrPort("10.0.0.2:53"))
	k2 := mkKey(netip.MustParseAddrPort("10.0.0.1:1001"), netip.MustParseAddrPort("10.0.0.2:53"))
	for _, reverse := range []bool{false, true} {
		for attempt := 0; attempt < 16; attempt++ {
			e := New(Config{MaxChannelEvts: 1})
			ca := netip.MustParseAddrPort("10.0.0.1:1000")
			sa := netip.MustParseAddrPort("10.0.0.2:53")
			ch := &channel{key: chanKey{client: ca.Addr(), server: sa.Addr(), port: 53, proto: "udp"}}
			add := func(k connKey, cp netip.AddrPort, n int64) {
				e.udp[k] = &udpFlow{client: cp, server: sa, ch: ch, burstBytes: n, inBurstBytes: n}
			}
			if reverse {
				add(k2, netip.MustParseAddrPort("10.0.0.1:1001"), 20)
				add(k1, ca, 10)
			} else {
				add(k1, ca, 10)
				add(k2, netip.MustParseAddrPort("10.0.0.1:1001"), 20)
			}
			e.flushUDP()
			if !reflect.DeepEqual(ch.burstS, []float64{10}) || !reflect.DeepEqual(ch.inBurstS, []float64{10}) {
				t.Fatalf("UDP winner burst=%v inbound=%v", ch.burstS, ch.inBurstS)
			}
		}
	}
}

func TestPM4RCadenceDNSMapOrderDoesNotChangeEntry(t *testing.T) {
	client := netip.MustParseAddr("10.0.0.9")
	build := func(reverse bool) cadenceEntry {
		e := New(Config{})
		e.dns.domains = map[string]*dnsDomain{}
		mk := func(key string, period float64) *dnsDomain {
			times := []float64{0, period, 2 * period, 3 * period, 4 * period, 5 * period}
			return &dnsDomain{base: "same.example", clients: map[netip.Addr]*dnsSeries{client: {t: times}}}
		}
		if reverse {
			e.dns.domains["b"] = mk("b", 64)
			e.dns.domains["a"] = mk("a", 5400)
		} else {
			e.dns.domains["a"] = mk("a", 5400)
			e.dns.domains["b"] = mk("b", 64)
		}
		return e.cadenceIndex().dests["same.example"][client.String()]
	}
	want := build(false)
	for i := 0; i < 64; i++ {
		got := build(i%2 == 1)
		if got != want {
			t.Fatalf("cadence entry differs: want %#v got %#v", want, got)
		}
	}
}

func pm4RBehaviorFinding(t *testing.T, reverse bool) []byte {
	t.Helper()
	e := New(Config{})
	client, server := netip.MustParseAddr("10.20.0.2"), netip.MustParseAddr("198.51.100.80")
	tls := &tlsAgg{conns: 1, certs: map[string]*certInfo{}}
	ja3 := []string{"00000000000000000000000000000001", "ffffffffffffffffffffffffffffffff"}
	ja4 := []string{"t13d1516h2_8daaf6152771_02713d6af862", "t13d1516h2_aabbccddeeff_112233445566"}
	ja3s := []string{"00000000000000000000000000000002", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}
	addCounts := func(c *counts, values []string) {
		if reverse {
			for i := len(values) - 1; i >= 0; i-- {
				c.inc(values[i])
			}
		} else {
			for _, v := range values {
				c.inc(v)
			}
		}
	}
	addCounts(&tls.ja3, ja3)
	addCounts(&tls.ja4, ja4)
	addCounts(&tls.ja3s, ja3s)
	certs := []string{"aaa-cert-hash", "zzz-cert-hash"}
	if reverse {
		for i := len(certs) - 1; i >= 0; i-- {
			h := certs[i]
			tls.certs[h] = &certInfo{SHA256: h, Subject: h}
		}
	} else {
		for _, h := range certs {
			tls.certs[h] = &certInfo{SHA256: h, Subject: h}
		}
	}
	e.iocs = map[string]map[string]string{"ja3": {}, "ja4": {}, "ja3s": {}, "cert": {}}
	for kind, values := range map[string][]string{"ja3": ja3, "ja4": ja4, "ja3s": ja3s} {
		e.iocs[kind][values[0]] = "alpha"
		e.iocs[kind][values[1]] = "omega"
	}
	e.iocs["cert"][certs[0]] = "alpha-cert"
	e.iocs["cert"][certs[1]] = "omega-cert"
	ch := &channel{key: chanKey{client: client, server: server, port: 443, proto: "tcp"}, tls: tls, conns: 1, first: time.Unix(1, 0), last: time.Unix(2, 0)}
	e.chOrder = []*channel{ch}
	findings := e.score()
	raw, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPM4RTLSIOCFindingsIgnoreMapInsertionOrder(t *testing.T) {
	want := pm4RBehaviorFinding(t, false)
	for i := 0; i < 64; i++ {
		got := pm4RBehaviorFinding(t, i%2 == 1)
		if string(got) != string(want) {
			t.Fatalf("findings vary with TLS IOC map insertion order at run %d\n%s\n%s", i, got, want)
		}
	}
}

func TestPM4RSignalTieSemanticsRemainFirstWriter(t *testing.T) {
	a := &acc{sigs: map[string]stats.Signal{}}
	a.add(stats.Signal{Name: "same", Score: 1, Weight: .2, Detail: "first"})
	a.add(stats.Signal{Name: "same", Score: 1, Weight: .2, Detail: "second"})
	if got := a.sigs["same"].Detail; got != "first" {
		t.Fatalf("equal contribution detail=%q", got)
	}
}

func TestPM4RDomainSortHasTotalOrder(t *testing.T) {
	keys := sortedDNSDomainKeys(map[string]*dnsDomain{"z": {}, "a": {}})
	if fmt.Sprint(keys) != "[a z]" {
		t.Fatal("DNS domain keys not sorted")
	}
}
