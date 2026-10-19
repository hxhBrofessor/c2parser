package eval

import (
	"bytes"
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"c2parser/internal/engine"
	"c2parser/internal/pcapio"
)

// pcapBuilder writes HTTP/1.1 request/response pairs on keep-alive TCP
// connections (handshake included, no retransmissions).
type pcapBuilder struct {
	t   *testing.T
	buf bytes.Buffer
	w   *pcapio.Writer
}

func newPcap(t *testing.T) *pcapBuilder {
	p := &pcapBuilder{t: t}
	w, err := pcapio.NewWriter(&p.buf, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	p.w = w
	return p
}

type conn struct {
	p          *pcapBuilder
	cli, srv   string
	cport      uint16
	cseq, sseq uint32
}

func (p *pcapBuilder) pkt(ts time.Time, src, dst string, sp, dp uint16, seq, ack uint32, syn, ackf bool, data []byte) {
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4()}
	tc := &layers.TCP{SrcPort: layers.TCPPort(sp), DstPort: layers.TCPPort(dp), Seq: seq, Ack: ack, SYN: syn, ACK: ackf, PSH: len(data) > 0, Window: 65535}
	tc.SetNetworkLayerForChecksum(ip)
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
	b := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tc, gopacket.Payload(data)); err != nil {
		p.t.Fatal(err)
	}
	if err := p.w.WritePacket(ts, b.Bytes()); err != nil {
		p.t.Fatal(err)
	}
}

func (p *pcapBuilder) open(ts time.Time, cli string, cport uint16, srv string) *conn {
	c := &conn{p: p, cli: cli, srv: srv, cport: cport, cseq: 1000, sseq: 5000}
	p.pkt(ts, cli, srv, cport, 80, c.cseq, 0, true, false, nil)
	c.cseq++
	p.pkt(ts.Add(time.Millisecond), srv, cli, 80, cport, c.sseq, c.cseq, true, true, nil)
	c.sseq++
	p.pkt(ts.Add(2*time.Millisecond), cli, srv, cport, 80, c.cseq, c.sseq, false, true, nil)
	return c
}

func (c *conn) exchange(ts time.Time, host string) {
	req := []byte("GET /poll HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: t\r\n\r\n")
	c.p.pkt(ts, c.cli, c.srv, c.cport, 80, c.cseq, c.sseq, false, true, req)
	c.cseq += uint32(len(req))
	resp := []byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	c.p.pkt(ts.Add(30*time.Millisecond), c.srv, c.cli, 80, c.cport, c.sseq, c.cseq, false, true, resp)
	c.sseq += uint32(len(resp))
}

func (p *pcapBuilder) save(dir, name string) string {
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, p.buf.Bytes(), 0o600); err != nil {
		p.t.Fatal(err)
	}
	return path
}

var t0 = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

func TestHarnessEndToEnd(t *testing.T) {
	dir := t.TempDir()
	r := mrand.New(mrand.NewPCG(8, 8))

	// benign: two clients, Poisson-timed polling of three services
	b := newPcap(t)
	for ci, cl := range []string{"10.9.0.1", "10.9.0.2"} {
		for si, sv := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
			c := b.open(t0, cl, uint16(40000+ci*10+si), sv)
			ts := t0
			for i := 0; i < 40; i++ {
				ts = ts.Add(time.Duration(60 * r.ExpFloat64() * float64(time.Second)))
				c.exchange(ts, fmt.Sprintf("svc%d.example", si))
			}
		}
	}
	benign := b.save(dir, "benign.pcap")

	// positive: 60 s shortening 30 % beacon, plus one background service
	p := newPcap(t)
	c := p.open(t0, "10.9.1.5", 41000, "203.0.113.9")
	ts := t0
	for i := 0; i < 50; i++ {
		ts = ts.Add(time.Duration(60 * (1 - 0.3*r.Float64()) * float64(time.Second)))
		c.exchange(ts, "c2.example")
	}
	bg := p.open(t0, "10.9.1.5", 41001, "198.51.100.7")
	ts = t0
	for i := 0; i < 30; i++ {
		ts = ts.Add(time.Duration(90 * r.ExpFloat64() * float64(time.Second)))
		bg.exchange(ts, "news.example")
	}
	pos := p.save(dir, "beacon.pcap")

	manifest := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(manifest, []byte(`captures:
  - path: benign.pcap
    licence: own
    benign: true
  - path: beacon.pcap
    licence: own
    framework: synthetic
    transport: http
    sleep: 60
    jitter: 30
    polarity: shortening
    c2:
      - client: 10.9.1.5
        server: 203.0.113.9
`), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := LoadManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if m.Captures[0].Path != benign || m.Captures[1].Path != pos {
		t.Fatalf("relative paths not resolved: %+v", m.Captures)
	}
	rep, err := Run(m, engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]int{}
	for _, s := range rep.Series {
		labels[s.Label]++
		if s.Label == "c2" && !strings.Contains(s.Key, "203.0.113.9") {
			t.Errorf("mislabelled c2 series %s", s.Key)
		}
	}
	if labels["c2"] == 0 || labels["benign"] < 6 || labels["background"] == 0 {
		t.Fatalf("labels %v", labels)
	}
	if _, ok := rep.Thresholds["v2"]; !ok {
		t.Fatalf("no v2 operating point: %+v", rep.Thresholds)
	}
	cell := rep.Cells["synthetic/http/60s/30%"]
	if cell["v2"] != 1 {
		t.Errorf("v2 TPR for the periodic cell = %v (thresholds %v)", cell["v2"], rep.Thresholds)
	}
	if rep.BenignHostHours <= 0 || len(rep.Notes) == 0 {
		t.Errorf("host-hours %.2f, notes %v (expect the small-sample note)", rep.BenignHostHours, rep.Notes)
	}
	out := filepath.Join(dir, "out")
	if err := rep.Write(out); err != nil {
		t.Fatal(err)
	}
	var back Report
	b2, _ := os.ReadFile(filepath.Join(out, "report.json"))
	if err := json.Unmarshal(b2, &back); err != nil || len(back.Series) != len(rep.Series) {
		t.Fatalf("report.json round trip: %v", err)
	}
	csvb, _ := os.ReadFile(filepath.Join(out, "series.csv"))
	if !strings.HasPrefix(string(csvb), "capture,framework,cell,label,") || strings.Count(string(csvb), "\n") != len(rep.Series)+1 {
		t.Errorf("series.csv malformed")
	}
}

func TestManifestRequiresLabels(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "m.yaml")
	_ = os.WriteFile(p, []byte("captures:\n  - path: x.pcap\n    framework: x\n"), 0o600)
	if _, err := LoadManifest(p); err == nil {
		t.Fatal("positive capture without c2 labels accepted")
	}
}

func TestRITALikeSeparates(t *testing.T) {
	r := mrand.New(mrand.NewPCG(9, 9))
	var per, poi []float64
	a, b := 0.0, 0.0
	for i := 0; i < 60; i++ {
		a += 60 * (1 - 0.1*r.Float64())
		b += 60 * r.ExpFloat64()
		per, poi = append(per, a), append(poi, b)
	}
	if x, y := RITALike(per, a), RITALike(poi, b); x <= y+0.2 {
		t.Errorf("RITA-like periodic %.2f vs Poisson %.2f", x, y)
	}
}

// v8a review #3: lower tail for cv/an, unknown cell labels, and host-hours
// counted for background-benign clients.
func TestReportTailsAndLabels(t *testing.T) {
	c := Capture{Framework: "havoc", Transport: "http"}
	if got := c.cell(); got != "havoc/http/unknown/unknown" {
		t.Errorf("cell label %q", got)
	}
	r := &Report{BenignQuantiles: map[string]Quantiles{}, Thresholds: map[string]float64{}, Cells: map[string]map[string]float64{},
		WorstHeldOut: map[string]string{}, FPPerHostHour: map[string]float64{}}
	for i := 0; i < 1000; i++ {
		cv := 0.3 + float64(i)/1000
		r.Series = append(r.Series, Series{Label: "benign", CV: &cv, V2: float64(i) / 1000})
	}
	r.summarise()
	if q := r.BenignQuantiles["cv"]; q.Tail != "lower" || q.Q[0] > 0.32 {
		t.Errorf("cv quantiles %+v, want lower tail near 0.31", q)
	}
	if q := r.BenignQuantiles["v2"]; q.Tail != "upper" || q.Q[0] < 0.98 {
		t.Errorf("v2 quantiles %+v, want upper tail", q)
	}
}

func TestBackgroundBenignHostHours(t *testing.T) {
	dir := t.TempDir()
	r := mrand.New(mrand.NewPCG(10, 10))
	p := newPcap(t)
	c := p.open(t0, "10.9.2.5", 42000, "203.0.113.19")
	ts := t0
	for i := 0; i < 40; i++ {
		ts = ts.Add(time.Duration(60 * (1 - 0.2*r.Float64()) * float64(time.Second)))
		c.exchange(ts, "c2.example")
	}
	bg := p.open(t0, "10.9.2.6", 42001, "198.51.100.8")
	ts = t0
	for i := 0; i < 40; i++ {
		ts = ts.Add(time.Duration(60 * r.ExpFloat64() * float64(time.Second)))
		bg.exchange(ts, "news.example")
	}
	p.save(dir, "bb.pcap")
	m := filepath.Join(dir, "m.yaml")
	_ = os.WriteFile(m, []byte("captures:\n  - path: bb.pcap\n    framework: synthetic\n    background_benign: true\n    c2:\n      - client: 10.9.2.5\n        server: 203.0.113.19\n"), 0o600)
	man, err := LoadManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Run(man, engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.BenignHostHours <= 0 {
		t.Fatalf("background-benign clients contributed no host-hours")
	}
	if _, ok := rep.FPPerHostHour["v2"]; !ok {
		t.Errorf("FP/host-hour missing with background_benign: %+v", rep.FPPerHostHour)
	}
}
