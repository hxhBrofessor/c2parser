package engine

import (
	"sort"
	"time"
)

// ConnRecord is one connection as c2parser saw it, for joining external
// labels (Zeek conn.log UIDs) in the eval harness. TCP: one record per
// tracked connection. UDP: one record per flow activity period, split at
// udpIdleSplit of silence like Zeek's udp_inactivity_timeout, so a reused
// 5-tuple maps to the same records Zeek would log.
type ConnRecord struct {
	Proto      string  `json:"proto"` // tcp | udp
	Client     string  `json:"client"`
	ClientPort uint16  `json:"client_port"`
	Server     string  `json:"server"`
	ServerPort uint16  `json:"server_port"`
	Start      float64 `json:"start"` // unix seconds
	Duration   float64 `json:"duration"`
}

const udpIdleSplit = time.Minute

func unixF(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

func (e *Engine) recordUDP(u *udpFlow, ts time.Time) {
	if u.rec > 0 {
		r := &e.udpRecs[u.rec-1]
		if end := r.Start + r.Duration; unixF(ts)-end <= udpIdleSplit.Seconds() {
			if d := unixF(ts) - r.Start; d > r.Duration {
				r.Duration = d
			}
			return
		}
	}
	e.udpRecs = append(e.udpRecs, ConnRecord{Proto: "udp", Client: u.client.Addr().String(), ClientPort: u.client.Port(),
		Server: u.server.Addr().String(), ServerPort: u.server.Port(), Start: unixF(ts)})
	u.rec = len(e.udpRecs)
}

func (e *Engine) connRecords() []ConnRecord {
	out := make([]ConnRecord, 0, len(e.allTCP)+len(e.udpRecs))
	for _, c := range e.allTCP {
		out = append(out, ConnRecord{Proto: "tcp", Client: c.client.Addr().String(), ClientPort: c.client.Port(),
			Server: c.server.Addr().String(), ServerPort: c.server.Port(), Start: unixF(c.start), Duration: c.last.Sub(c.start).Seconds()})
	}
	out = append(out, e.udpRecs...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}
