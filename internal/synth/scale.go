package synth

import (
	"fmt"
	"io"
	"math/rand/v2"
	"time"

	"github.com/google/gopacket/layers"
)

// Scale is the flow-heavy scale scenario (v9c 3.2): many short one-shot
// connections — plain HTTP, TLS and DNS lookups from a pool of internal
// clients to a large pool of external servers — plus one embedded
// periodic TLS series (the needle). Packets are written in time order as
// they are generated, so memory stays flat however large the capture.
type Scale struct {
	Conns    int           // TCP one-shot connections (HTTP + TLS)
	DNS      int           // DNS query/response pairs
	Clients  int           // internal clients (10.20.0.0/16)
	Servers  int           // external servers (198.18.0.0/15)
	TLSShare float64       // fraction of TCP one-shots that are TLS
	Duration time.Duration // capture span
	Seed     uint64
	// Needle: client NeedleClient → NeedleServer, SNI NeedleName, every
	// NeedleSleep ± 10 % (shortening).
	NeedleClient, NeedleServer, NeedleName string
	NeedleSleep                            time.Duration
}

// DefaultScale is the v9c 3.2 configuration: 500k TCP one-shots, 200k DNS.
func DefaultScale() Scale {
	return Scale{Conns: 500_000, DNS: 200_000, Clients: 2000, Servers: 50_000, TLSShare: 0.4,
		Duration: 2 * time.Hour, Seed: 1,
		NeedleClient: "10.9.9.9", NeedleServer: "203.0.113.250", NeedleName: "rare-sync.example", NeedleSleep: 60 * time.Second}
}

// ScaleInfo summarises what WriteScale produced.
type ScaleInfo struct {
	Packets, TCPConns, DNSPairs, NeedleEvents int
}

func (s Scale) client(i int) string { return fmt.Sprintf("10.20.%d.%d", (i/250)%250, 1+i%250) }
func (s Scale) server(i int) string {
	return fmt.Sprintf("198.%d.%d.%d", 18+(i>>16)&1, (i>>8)&0xff, 1+i&0xfe)
}

// WriteScale streams the scale capture as a classic pcap.
func WriteScale(w io.Writer, s Scale) (ScaleInfo, error) {
	b, err := NewPcap(w)
	if err != nil {
		return ScaleInfo{}, err
	}
	r := rand.New(rand.NewPCG(s.Seed, 0x5ca1e))
	slots := s.Conns + s.DNS
	step := s.Duration / time.Duration(slots+1)
	if step < 5*time.Millisecond {
		return ScaleInfo{}, fmt.Errorf("scale: %d events in %v leave %v per event (need ≥ 5 ms)", slots, s.Duration, step)
	}
	start := time.Date(2024, 3, 25, 12, 0, 0, 0, time.UTC)
	var info ScaleInfo
	nextNeedle := start.Add(s.NeedleSleep)
	dnsLeft, tcpLeft := s.DNS, s.Conns
	port := map[string]uint16{}
	sport := func(cl string) uint16 {
		p := port[cl]
		if p < 49152 {
			p = 49152
		}
		port[cl] = p + 1
		if p == 65535 {
			port[cl] = 49152
		}
		return p
	}
	for i := 0; i < slots; i++ {
		ts := start.Add(time.Duration(i) * step)
		if s.NeedleSleep > 0 && !ts.Before(nextNeedle) {
			t := b.TCP(ts, s.NeedleClient, sport(s.NeedleClient), s.NeedleServer, 443)
			x := t.Send(ts.Add(2200*time.Microsecond), true, ClientHello(s.NeedleName, []string{"http/1.1"}), 1400)
			x = t.Send(x.Add(100*time.Microsecond), false, AppData(RandBytes(r, 300)), 1400)
			x = t.Send(x.Add(100*time.Microsecond), true, AppData(RandBytes(r, 120)), 1400)
			t.Close(x.Add(100 * time.Microsecond))
			if t.Err != nil {
				return info, t.Err
			}
			info.NeedleEvents++
			info.TCPConns++
			nextNeedle = nextNeedle.Add(time.Duration(float64(s.NeedleSleep) * (1 - 0.1*r.Float64())))
			continue
		}
		cl := s.client(r.IntN(s.Clients))
		srv := s.server(r.IntN(s.Servers))
		// interleave DNS and TCP in proportion
		if dnsLeft > 0 && (tcpLeft == 0 || r.IntN(dnsLeft+tcpLeft) < dnsLeft) {
			dnsLeft--
			name := fmt.Sprintf("www.site%d.com", r.IntN(s.Servers))
			id := uint16(r.IntN(65536))
			if err := b.DNSQuery(ts, cl, "10.20.255.53", name, layers.DNSTypeA, id); err != nil {
				return info, err
			}
			ans := []layers.DNSResourceRecord{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 300, IP: []byte{198, 18, byte(id >> 8), byte(id)}}}
			if err := b.DNSResp(ts.Add(time.Millisecond), cl, "10.20.255.53", name, layers.DNSTypeA, id, layers.DNSResponseCodeNoErr, ans); err != nil {
				return info, err
			}
			info.DNSPairs++
			continue
		}
		tcpLeft--
		info.TCPConns++
		if r.Float64() < s.TLSShare {
			t := b.TCP(ts, cl, sport(cl), srv, 443)
			x := t.Send(ts.Add(2200*time.Microsecond), true, ClientHello(fmt.Sprintf("s%d.example.net", r.IntN(s.Servers)), []string{"h2", "http/1.1"}), 1400)
			x = t.Send(x.Add(100*time.Microsecond), false, AppData(RandBytes(r, 300)), 1400)
			x = t.Send(x.Add(100*time.Microsecond), true, AppData(RandBytes(r, 100+r.IntN(200))), 1400)
			x = t.Send(x.Add(100*time.Microsecond), false, AppData(RandBytes(r, 200+r.IntN(800))), 1400)
			t.Close(x.Add(100 * time.Microsecond))
			if t.Err != nil {
				return info, t.Err
			}
			continue
		}
		t := b.TCP(ts, cl, sport(cl), srv, 80)
		host := fmt.Sprintf("www.site%d.com", r.IntN(s.Servers))
		x := t.Send(ts.Add(2200*time.Microsecond), true, HTTPReq("GET", fmt.Sprintf("/item/%d", r.IntN(100000)), []string{"Host: " + host,
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language: en-US,en;q=0.9",
			"Accept-Encoding: gzip, deflate", "Connection: close"}, ""), 1400)
		x = t.Send(x.Add(200*time.Microsecond), false, HTTPResp("HTTP/1.1 200 OK", []string{"Content-Type: text/html"}, "<html>ok</html>"), 1400)
		t.Close(x.Add(100 * time.Microsecond))
		if t.Err != nil {
			return info, t.Err
		}
	}
	info.Packets = b.Count
	return info, nil
}
