package synth

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"c2parser/internal/pcapio"
)

// ZeekConn is one connection in a synthetic Zeek conn.log.
type ZeekConn struct {
	UID          string
	TS           time.Time
	Last         time.Time
	Proto        string
	OrigH, RespH netip.Addr
	OrigP, RespP uint16
	OrigBytes    int64
	RespBytes    int64
	Packets      int
}

// ZeekConns derives Zeek-style connections from a capture, independently
// of the engine (it shares no code with internal/engine): TCP connections
// start at a SYN (or at the first packet of an unseen 5-tuple) and end at
// FIN/RST from both sides or RST; UDP "connections" split after 60 s of
// silence, as Zeek's udp_inactivity_timeout does. The originator is the
// SYN sender, else the first sender. UIDs are deterministic.
func ZeekConns(r pcapio.Reader) ([]ZeekConn, error) {
	type key struct {
		proto string
		a, b  netip.AddrPort
	}
	type state struct {
		c                *ZeekConn
		finO, finR, done bool
	}
	canon := func(proto string, s, d netip.AddrPort) key {
		if d.Addr().Less(s.Addr()) || d.Addr() == s.Addr() && d.Port() < s.Port() {
			s, d = d, s
		}
		return key{proto, s, d}
	}
	open := map[key]*state{}
	var conns []*ZeekConn
	newConn := func(proto string, ts time.Time, s, d netip.AddrPort) *state {
		c := &ZeekConn{TS: ts, Last: ts, Proto: proto, OrigH: s.Addr(), OrigP: s.Port(), RespH: d.Addr(), RespP: d.Port()}
		conns = append(conns, c)
		return &state{c: c}
	}
	for {
		p, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		pkt := gopacket.NewPacket(p.Data, p.LinkType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		var src, dst netip.Addr
		switch nl := pkt.NetworkLayer().(type) {
		case *layers.IPv4:
			src, _ = netip.AddrFromSlice(nl.SrcIP.To4())
			dst, _ = netip.AddrFromSlice(nl.DstIP.To4())
		case *layers.IPv6:
			src, _ = netip.AddrFromSlice(nl.SrcIP)
			dst, _ = netip.AddrFromSlice(nl.DstIP)
		default:
			continue
		}
		ts := p.Timestamp
		switch tl := pkt.TransportLayer().(type) {
		case *layers.TCP:
			s, d := netip.AddrPortFrom(src, uint16(tl.SrcPort)), netip.AddrPortFrom(dst, uint16(tl.DstPort))
			k := canon("tcp", s, d)
			st := open[k]
			if st == nil || st.done || tl.SYN && !tl.ACK && ts.Sub(st.c.Last) > time.Second {
				if tl.SYN && tl.ACK { // SYN-ACK first: the receiver originated
					s, d = d, s
				}
				st = newConn("tcp", ts, s, d)
				open[k] = st
			}
			c := st.c
			c.Packets++
			if ts.After(c.Last) {
				c.Last = ts
			}
			fromOrig := s.Addr() == c.OrigH && s.Port() == c.OrigP
			if fromOrig {
				c.OrigBytes += int64(len(tl.Payload))
			} else {
				c.RespBytes += int64(len(tl.Payload))
			}
			if tl.RST {
				st.done = true
			}
			if tl.FIN {
				if fromOrig {
					st.finO = true
				} else {
					st.finR = true
				}
				st.done = st.finO && st.finR
			}
		case *layers.UDP:
			s, d := netip.AddrPortFrom(src, uint16(tl.SrcPort)), netip.AddrPortFrom(dst, uint16(tl.DstPort))
			k := canon("udp", s, d)
			st := open[k]
			if st == nil || ts.Sub(st.c.Last) > time.Minute {
				st = newConn("udp", ts, s, d)
				open[k] = st
			}
			c := st.c
			c.Packets++
			if ts.After(c.Last) {
				c.Last = ts
			}
			if s.Addr() == c.OrigH && s.Port() == c.OrigP {
				c.OrigBytes += int64(len(tl.Payload))
			} else {
				c.RespBytes += int64(len(tl.Payload))
			}
		}
	}
	out := make([]ZeekConn, len(conns))
	for i, c := range conns {
		c.UID = zeekUID(uint64(i) + 1)
		out[i] = *c
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TS.Before(out[j].TS) })
	return out, nil
}

// zeekUID is a Zeek-looking UID ("C" + 17 base62 chars) from a counter
// (two splitmix64 rounds: unique per n, stable across runs).
func zeekUID(n uint64) string {
	const alpha = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	mix := func(z uint64) uint64 {
		z += 0x9e3779b97f4a7c15
		z = (z ^ z>>30) * 0xbf58476d1ce4e5b9
		z = (z ^ z>>27) * 0x94d049bb133111eb
		return z ^ z>>31
	}
	hi, lo := mix(n), mix(n^0xc2c2c2c2c2c2c2c2)
	b := []byte{'C'}
	for i := 0; i < 17; i++ {
		x := lo
		if i >= 9 {
			x = hi
		}
		b = append(b, alpha[x%62])
		if i >= 9 {
			hi /= 62
		} else {
			lo /= 62
		}
	}
	return string(b)
}

func zeekTS(t time.Time) string { return fmt.Sprintf("%.6f", float64(t.UnixNano())/1e9) }

// WriteZeekTSV writes conns as a Zeek TSV conn.log (the standard header
// and the first conn.log columns).
func WriteZeekTSV(w io.Writer, conns []ZeekConn) error {
	bw := bufio.NewWriter(w)
	open := time.Unix(0, 0).UTC()
	if len(conns) > 0 {
		open = conns[0].TS.UTC()
	}
	fmt.Fprintf(bw, "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n#open\t%s\n", open.Format("2006-01-02-15-04-05"))
	fmt.Fprintf(bw, "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\n")
	fmt.Fprintf(bw, "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\n")
	for _, c := range conns {
		fmt.Fprintf(bw, "%s\t%s\t%s\t%d\t%s\t%d\t%s\t-\t%.6f\t%d\t%d\t-\n", zeekTS(c.TS), c.UID, c.OrigH, c.OrigP, c.RespH, c.RespP,
			c.Proto, c.Last.Sub(c.TS).Seconds(), c.OrigBytes, c.RespBytes)
	}
	fmt.Fprintf(bw, "#close\t%s\n", open.Format("2006-01-02-15-04-05"))
	return bw.Flush()
}

// WriteZeekJSON writes conns as Zeek JSON lines.
func WriteZeekJSON(w io.Writer, conns []ZeekConn) error {
	enc := json.NewEncoder(w)
	for _, c := range conns {
		if err := enc.Encode(map[string]any{"ts": float64(c.TS.UnixNano()) / 1e9, "uid": c.UID, "id.orig_h": c.OrigH.String(),
			"id.orig_p": c.OrigP, "id.resp_h": c.RespH.String(), "id.resp_p": c.RespP, "proto": c.Proto,
			"duration": c.Last.Sub(c.TS).Seconds(), "orig_bytes": c.OrigBytes, "resp_bytes": c.RespBytes}); err != nil {
			return err
		}
	}
	return nil
}

// LabelRow is one row of a synthetic label file (JSON lines, keyed by UID).
type LabelRow struct {
	UID       string  `json:"uid"`
	Label     string  `json:"label"` // c2 | benign
	Framework string  `json:"framework,omitempty"`
	Transport string  `json:"transport,omitempty"`
	Sleep     float64 `json:"sleep,omitempty"`
	Jitter    float64 `json:"jitter,omitempty"`
}

// LabelConns labels each connection c2 when its endpoints match one of
// the manifest row's wire endpoints (client IP + server IP, either
// direction), else benign. Positive rows carry the row's cell metadata.
func LabelConns(conns []ZeekConn, me *ManifestEntry) []LabelRow {
	pos := map[[2]string]bool{}
	for _, ep := range me.Wire {
		pos[[2]string{ep.Client, ep.Server}] = true
		pos[[2]string{ep.Server, ep.Client}] = true
	}
	out := make([]LabelRow, len(conns))
	for i, c := range conns {
		out[i] = LabelRow{UID: c.UID, Label: "benign"}
		if pos[[2]string{c.OrigH.String(), c.RespH.String()}] {
			out[i] = LabelRow{UID: c.UID, Label: "c2", Framework: me.Framework, Transport: me.Transport, Sleep: me.Sleep, Jitter: me.Jitter}
		}
	}
	return out
}

// WriteLabels writes label rows as JSON lines.
func WriteLabels(w io.Writer, rows []LabelRow) error {
	enc := json.NewEncoder(w)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}

// wireIPs are the server IPs a C2 stream's packets actually go to.
func wireIPs(st Stream) []string {
	var ips []string
	if st.Topology.Proxy != "" {
		if h, _, ok := strings.Cut(st.Topology.Proxy, ":"); ok {
			return []string{h}
		}
	}
	if r := st.Topology.Redirectors; r != nil && len(r.IPs) > 0 {
		return append(ips, r.IPs...)
	}
	return append(ips, st.Server)
}
