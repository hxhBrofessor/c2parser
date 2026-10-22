package engine

import (
	"sort"
	"strings"

	"c2parser/internal/stats"
)

// HTTPChannelSummary is a per client/server/host roll-up of HTTP traffic.
type HTTPChannelSummary struct {
	Client     string           `json:"client"`
	Server     string           `json:"server"`
	Port       uint16           `json:"port"`
	Host       string           `json:"host"`
	Requests   int              `json:"requests"`
	Responses  int              `json:"responses"`
	UploadB    int64            `json:"upload_bytes"`
	DownloadB  int64            `json:"download_bytes"`
	RandomUp   int              `json:"random_bodies_up"`
	RandomDown int              `json:"random_bodies_down"`
	LegacyHits int              `json:"legacy_entropy_hits"`
	UserAgent  string           `json:"user_agent,omitempty"`
	Beacon     *stats.Beacon    `json:"beacon,omitempty"` // v1 metrics (display)
	MaxRandom  stats.Assessment `json:"max_randomness"`
	Notable    []NotableMessage `json:"notable_messages,omitempty"`
	SigHits    map[string]int   `json:"signature_hits,omitempty"`
	Anomalies  map[string]int   `json:"header_anomalies,omitempty"`
	FirstFrame int64            `json:"first_frame"`
}

func (e *Engine) httpSummaries() []HTTPChannelSummary {
	// Busiest channels first, at most MaxSummaryRows (v9c 3.3: a summary
	// row per one-shot channel is most of the output and memory on
	// flow-heavy captures). Same order as sorting all rows.
	chans := append([]*httpChannel(nil), e.httpOrder...)
	sort.SliceStable(chans, func(i, j int) bool {
		return chans[i].requests+chans[i].responses > chans[j].requests+chans[j].responses
	})
	if len(chans) > e.cfg.MaxSummaryRows {
		e.counters.SummaryRowsDropped += int64(len(chans) - e.cfg.MaxSummaryRows)
		chans = chans[:e.cfg.MaxSummaryRows]
	}
	out := make([]HTTPChannelSummary, 0, len(chans))
	for _, h := range chans {
		s := HTTPChannelSummary{
			Client: h.key.client.String(), Server: h.key.server.String(), Port: h.key.port, Host: h.key.host,
			Requests: h.requests, Responses: h.responses, UploadB: h.upload, DownloadB: h.download,
			RandomUp: h.randomUp, RandomDown: h.randomDn, LegacyHits: h.legacyHits, UserAgent: topKey(h.uas.Map()),
			MaxRandom: h.maxRandom, Notable: h.notable, SigHits: h.sigHits, Anomalies: h.anomalies, FirstFrame: h.firstFrame,
		}
		// Display summary only (not scoring): always the v1 beacon metrics;
		// v2 metrics for the same series are in Result.Timing.
		if b, ok := stats.ScoreBeacon(h.reqT, h.reqSize, e.cfg.Beacon); ok {
			s.Beacon = &b
		}
		out = append(out, s)
	}
	return out
}

// SMBFileSummary describes one file or pipe seen over SMB.
type SMBFileSummary struct {
	Client       string   `json:"client"`
	Server       string   `json:"server"`
	Share        string   `json:"share"`
	Name         string   `json:"name"`
	Pipe         bool     `json:"pipe"`
	NameKnown    bool     `json:"name_known"`
	WriteBytes   int64    `json:"write_bytes"`
	ReadBytes    int64    `json:"read_bytes"`
	Writes       int      `json:"writes"`
	Reads        int      `json:"reads"`
	Transceives  int      `json:"transceives"`
	C2Magic      int      `json:"c2_magic_hits"`
	Users        []string `json:"users,omitempty"`
	FirstFrame   int64    `json:"first_frame"`
	Opens        int      `json:"opens,omitempty"`         // FileIds merged into this row
	NameInferred bool     `json:"name_inferred,omitempty"` // naming request lost; see smbState.consolidate
}

// SMB connection-level notes are folded into file summaries; encrypted
// sessions appear as a pseudo-file so they aren't silently dropped.
func (e *Engine) smbSummaries() []SMBFileSummary {
	var out []SMBFileSummary
	for _, st := range e.smbStates {
		st.consolidate()
		users := sortedKeys(st.users)
		for _, f := range st.order {
			out = append(out, SMBFileSummary{
				Client: st.c.client.Addr().String(), Server: st.c.server.Addr().String(), Share: f.Share, Name: f.Name,
				Pipe: f.isPipe(), NameKnown: f.NameKnown, WriteBytes: f.WriteBytes, ReadBytes: f.ReadBytes,
				Writes: f.Writes, Reads: f.Reads, Transceives: f.Transceives, C2Magic: f.magicHits, Users: users, FirstFrame: f.firstFrame,
				Opens: f.opens, NameInferred: f.inferred,
			})
		}
		if st.encMsgs > 0 {
			out = append(out, SMBFileSummary{Client: st.c.client.Addr().String(), Server: st.c.server.Addr().String(),
				Name: "<SMB3 encrypted session: content not visible>", ReadBytes: st.encBytes, Users: users})
		}
	}
	sortSMBSummaries(out)
	return out
}

func sortSMBSummaries(out []SMBFileSummary) {
	sort.SliceStable(out, func(i, j int) bool { return out[i].WriteBytes+out[i].ReadBytes > out[j].WriteBytes+out[j].ReadBytes })
}

// DNSDomainSummary describes queries under one registrable domain.
type DNSDomainSummary struct {
	Domain       string         `json:"domain"`
	Queries      int            `json:"queries"`
	Responses    int            `json:"responses"`
	NXDomain     int            `json:"nxdomain"`
	UniqueSubs   int            `json:"unique_subdomains"`
	AvgSubLen    float64        `json:"avg_subdomain_len"`
	MaxLabel     int            `json:"max_label_len"`
	Alphabet     string         `json:"subdomain_alphabet"`
	Randomness   float64        `json:"subdomain_randomness"`
	EncodedBytes int64          `json:"encoded_bytes_estimate"`
	TXTBytes     int64          `json:"txt_null_answer_bytes"`
	QTypes       map[string]int `json:"qtypes"`
	Clients      int            `json:"clients"`
	Samples      []string       `json:"longest_names,omitempty"`
	Logical      int            `json:"logical_queries"`
	Retries      int            `json:"retries_and_twins"`
	Cardinality  float64        `json:"name_cardinality_ratio"`
	RawCard      float64        `json:"raw_cardinality_ratio"`
	Positional   positional     `json:"positional"`
	LuiseMean    float64        `json:"luise_name_entropy_mean"`
	LuiseMax     float64        `json:"luise_name_entropy_max"`
	TTL0Share    float64        `json:"ttl0_share"`
}

func (e *Engine) dnsSummaries() []DNSDomainSummary {
	doms := make([]*dnsDomain, 0, len(e.dns.domains))
	for _, d := range e.dns.domains {
		doms = append(doms, d)
	}
	// Most unique subdomains, then most queries, then name (deterministic;
	// v9b tied in map order). At most MaxSummaryRows rows.
	sort.Slice(doms, func(i, j int) bool {
		a, b := doms[i], doms[j]
		if len(a.subs) != len(b.subs) {
			return len(a.subs) > len(b.subs)
		}
		if a.queries != b.queries {
			return a.queries > b.queries
		}
		return a.base < b.base
	})
	if len(doms) > e.cfg.MaxSummaryRows {
		e.counters.SummaryRowsDropped += int64(len(doms) - e.cfg.MaxSummaryRows)
		doms = doms[:e.cfg.MaxSummaryRows]
	}
	out := make([]DNSDomainSummary, 0, len(doms))
	for _, d := range doms {
		ft := e.dnsFeatures(d)
		sum := DNSDomainSummary{
			Domain: d.base, Queries: d.queries, Responses: d.responses, NXDomain: d.nx, UniqueSubs: ft.u, AvgSubLen: round2(ft.avgLen),
			MaxLabel: d.maxLabel, Alphabet: string(ft.agg.Alphabet), Randomness: round2(ft.r), EncodedBytes: int64(ft.encoded),
			TXTBytes: d.txtBytes, QTypes: d.qtypes, Clients: len(d.clients), Samples: d.samples,
			Logical: d.logical, Retries: d.retries, Cardinality: round2(ft.ratio), RawCard: round2(ft.rawRatio), Positional: ft.pos,
			LuiseMax: round2(d.luiseMax),
		}
		if ft.u > 0 {
			sum.LuiseMean = round2(d.luiseSum / float64(ft.u))
		}
		if d.answerRRs > 0 {
			sum.TTL0Share = round2(float64(d.ttl0) / float64(d.answerRRs))
		}
		out = append(out, sum)
	}
	return out
}

// ChannelSummary is a client→service traffic roll-up.
type ChannelSummary struct {
	Client      string   `json:"client"`
	Server      string   `json:"server"`
	ServerNames []string `json:"server_names,omitempty"`
	Port        uint16   `json:"port"`
	Proto       string   `json:"proto"`
	Conns       int      `json:"connections"`
	OutBytes    int64    `json:"out_bytes"`
	InBytes     int64    `json:"in_bytes"`
	PCR         float64  `json:"pcr"`
	LongestSec  float64  `json:"longest_conn_sec"`
	QUIC        bool     `json:"quic,omitempty"`
	SNI         string   `json:"sni,omitempty"`
	JA3         string   `json:"ja3,omitempty"`
	JA4         string   `json:"ja4,omitempty"`
	JA3S        string   `json:"ja3s,omitempty"`
	CertSubject string   `json:"cert_subject,omitempty"`
}

func (e *Engine) topTalkers(n int) []ChannelSummary {
	chs := append([]*channel(nil), e.chOrder...)
	sort.SliceStable(chs, func(i, j int) bool { return chs[i].out+chs[i].in > chs[j].out+chs[j].in })
	var out []ChannelSummary
	for i, c := range chs {
		if i == n {
			break
		}
		cs := ChannelSummary{Client: c.key.client.String(), Server: c.key.server.String(), ServerNames: e.namesOf(c.key.server),
			Port: c.key.port, Proto: c.key.proto, Conns: c.conns, OutBytes: c.out, InBytes: c.in, PCR: round2(pcr(c.out, c.in)),
			LongestSec: round2(c.maxConnSec), QUIC: c.quic}
		if t := c.tls; t != nil {
			cs.SNI = sortedKeysInt(t)
			cs.JA3, _ = topCount(t.ja3.Map())
			cs.JA4, _ = topCount(t.ja4.Map())
			cs.JA3S, _ = topCount(t.ja3s.Map())
			for _, hash := range sortedCertHashes(t) {
				cs.CertSubject = t.certs[hash].Subject
				break
			}
		}
		out = append(out, cs)
	}
	return out
}

// RPCCall is one DCE/RPC operation seen on the wire, aggregated per
// (client, server, endpoint, op, transport) (v9 Phase 1.2 / rev 2 0.2).
type RPCCall struct {
	Client     string   `json:"client"`
	Server     string   `json:"server"`
	Transport  string   `json:"transport"` // smb-pipe | tcp
	Pipes      []string `json:"pipes,omitempty"`
	Ports      []uint16 `json:"ports,omitempty"` // tcp: server ports
	Endpoint   string   `json:"endpoint"`        // interface name; the pipe name (smb) or "unbound" (tcp) when the BIND wasn't captured
	Op         string   `json:"op"`
	Count      int      `json:"count"`
	Bound      bool     `json:"bound"`                // false: the BIND wasn't captured
	Learned    string   `json:"learned,omitempty"`    // ept_map | oxid: interface/port learned from a mapper response
	AuthLevel  string   `json:"auth_level,omitempty"` // highest MS-RPCE auth level seen (none … privacy)
	FirstFrame int64    `json:"first_frame,omitempty"`
	LastFrame  int64    `json:"last_frame,omitempty"`
}

func (e *Engine) rpcCalls() []RPCCall {
	agg := map[string]*RPCCall{}
	var order []string
	for _, as := range e.rpcAssocs() {
		cl, sv := as.client.Addr().String(), as.server.Addr().String()
		for k, n := range as.st.calls {
			ep, op, _ := strings.Cut(k, ":")
			key := cl + "|" + sv + "|" + ep + "|" + op + "|" + as.st.transport
			r := agg[key]
			if r == nil {
				r = &RPCCall{Client: cl, Server: sv, Transport: as.st.transport, Endpoint: ep, Op: op, Bound: true}
				agg[key] = r
				order = append(order, key)
			}
			r.Count += n
			r.Bound = r.Bound && !as.st.unbound[k]
			if as.pipe != "" && !containsStr(r.Pipes, as.pipe) {
				r.Pipes = append(r.Pipes, as.pipe)
			}
			if as.st.transport == "tcp" && !containsU16(r.Ports, as.server.Port()) {
				r.Ports = append(r.Ports, as.server.Port())
			}
			if l := as.st.learned[k]; l != "" {
				r.Learned = l
			}
			if lv := as.st.auth[k]; lv > 0 && (r.AuthLevel == "" || lv > authLevelOf(r.AuthLevel)) {
				r.AuthLevel = authLevelName[lv]
			}
			fr := as.st.frames[k]
			if r.FirstFrame == 0 || (fr[0] > 0 && fr[0] < r.FirstFrame) {
				r.FirstFrame = fr[0]
			}
			if fr[1] > r.LastFrame {
				r.LastFrame = fr[1]
			}
		}
	}
	sort.Strings(order)
	out := make([]RPCCall, 0, len(order))
	for _, k := range order {
		r := agg[k]
		sort.Slice(r.Ports, func(i, j int) bool { return r.Ports[i] < r.Ports[j] })
		out = append(out, *r)
	}
	return out
}

func authLevelOf(name string) uint8 {
	for k, v := range authLevelName {
		if v == name {
			return k
		}
	}
	return 0
}

func containsU16(xs []uint16, v uint16) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
