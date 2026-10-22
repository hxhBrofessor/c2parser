package engine

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket/layers"

	"c2parser/internal/pcapio"
	sy "c2parser/internal/synth"
)

func TestReuseSYNRetransmissionBelowThresholdKeepsGeneration(t *testing.T) {
	s := newSynth(t)
	const client, server = "10.8.0.5", "10.8.0.20"
	const clientPort, serverPort = 50103, 80
	conn := s.tcp(s.now, client, clientPort, server, serverPort)

	// Repeat the original SYN (ISN 1000) before the 30-second boundary.
	ip := sy.IP4(client, server, layers.IPProtocolTCP)
	syn := &layers.TCP{SrcPort: layers.TCPPort(clientPort), DstPort: layers.TCPPort(serverPort), Seq: 1000, SYN: true, Window: 65535}
	if err := syn.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	if err := s.b.Write(s.now.Add(3*time.Millisecond), sy.Eth(), ip, syn); err != nil {
		t.Fatal(err)
	}
	conn.Send(s.now.Add(5*time.Millisecond), true,
		httpReq("GET", "/once", []string{"Host: reuse.example"}, ""), 1400)

	path := filepath.Join(t.TempDir(), "syn-retransmit.pcap")
	if err := os.WriteFile(path, s.buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := pcapio.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	e := New(Config{RecordConns: true})
	if err := e.Ingest(r); err != nil {
		_ = r.Close()
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	key := mkKey(netip.MustParseAddrPort("10.8.0.5:50103"), netip.MustParseAddrPort("10.8.0.20:80"))
	if len(e.allTCP) != 1 {
		t.Fatalf("connection generations=%d, want 1", len(e.allTCP))
	}
	if got := e.tcp[key].reuseFrame; got != 0 {
		t.Fatalf("SYN retransmission allocated reuse namespace at frame %d, want none", got)
	}
	res := e.Finish()
	if res.Counters.TCPConns != 1 || res.Counters.HTTPMessages != 1 {
		t.Fatalf("connections=%d HTTP messages=%d, want 1/1", res.Counters.TCPConns, res.Counters.HTTPMessages)
	}
}
