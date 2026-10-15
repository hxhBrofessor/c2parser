package perturb

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sort"
	"time"

	"c2parser/internal/synth"
)

// Channel selects one C2 channel: TCP between Client and Server (Port 0 =
// any server port), across all its connections.
type Channel struct {
	Client netip.Addr
	Server netip.Addr
	Port   uint16
}

// Txn is one request→response transaction on a channel.
type Txn struct {
	Start, End time.Time
	ReqBytes   int   // client→server payload bytes
	RespBytes  int   // server→client payload bytes
	Packets    []int // indices into the packet slice
}

func (c Channel) match(f frame) (fromClient, ok bool) {
	if f.proto != 6 || f.l4 < 0 {
		return false, false
	}
	s, d := netip.AddrFrom4(f.src), netip.AddrFrom4(f.dst)
	switch {
	case s == c.Client && d == c.Server && (c.Port == 0 || f.dport == c.Port):
		return true, true
	case s == c.Server && d == c.Client && (c.Port == 0 || f.sport == c.Port):
		return false, true
	}
	return false, false
}

// Transactions splits a channel into transactions. A transaction starts at
// a client data segment that follows server data (or opens the
// connection's first exchange); the handshake joins the connection's first
// transaction and trailing ACK/FIN packets join the one before them.
// Packets are taken in time order.
func Transactions(pkts []Packet, c Channel) []Txn {
	idx := make([]int, len(pkts))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return pkts[idx[a]].Timestamp.Before(pkts[idx[b]].Timestamp) })
	type connState struct {
		cur        int // current txn, -1 none
		serverLast bool
		pending    []int
	}
	conns := map[flowKey]*connState{}
	var txns []Txn
	for _, i := range idx {
		f, ok := parse(pkts[i])
		if !ok {
			continue
		}
		fromClient, ok := c.match(f)
		if !ok {
			continue
		}
		k := f.key()
		st := conns[k]
		if st == nil {
			st = &connState{cur: -1}
			conns[k] = st
		}
		data := f.plen > 0
		if fromClient && data && (st.cur < 0 || st.serverLast) {
			txns = append(txns, Txn{})
			st.cur = len(txns) - 1
			st.serverLast = false
			txns[st.cur].Packets = append(txns[st.cur].Packets, st.pending...)
			st.pending = nil
		}
		if st.cur < 0 {
			st.pending = append(st.pending, i)
			continue
		}
		t := &txns[st.cur]
		t.Packets = append(t.Packets, i)
		if data {
			if fromClient {
				t.ReqBytes += f.plen
			} else {
				t.RespBytes += f.plen
				st.serverLast = true
			}
		}
	}
	for i := range txns {
		t := &txns[i]
		sort.Ints(t.Packets)
		for j, pi := range t.Packets {
			ts := pkts[pi].Timestamp
			if j == 0 || ts.Before(t.Start) {
				t.Start = ts
			}
			if ts.After(t.End) {
				t.End = ts
			}
		}
	}
	sort.SliceStable(txns, func(a, b int) bool { return txns[a].Start.Before(txns[b].Start) })
	return txns
}

// RetimeTo moves transaction i of channel c to start at starts[i], keeping
// every packet's offset within its transaction, all bytes, and TCP
// seq/ack. A transaction never starts before the previous one on the same
// connection has ended (it is pushed back 1 ms past it). Other packets are
// untouched. Output is time-sorted.
func RetimeTo(pkts []Packet, c Channel, starts []time.Time) ([]Packet, Change, error) {
	txns := Transactions(pkts, c)
	if len(txns) == 0 {
		return nil, Change{}, fmt.Errorf("retime: no transactions on %v → %v:%d", c.Client, c.Server, c.Port)
	}
	if len(starts) < len(txns) {
		return nil, Change{}, fmt.Errorf("retime: %d start times for %d transactions", len(starts), len(txns))
	}
	out := clone(pkts)
	connEnd := map[flowKey]time.Time{}
	pushed := 0
	for i, t := range txns {
		f, _ := parse(pkts[t.Packets[0]])
		k := f.key()
		s := starts[i]
		if e, ok := connEnd[k]; ok && !s.After(e) {
			s = e.Add(time.Millisecond)
			pushed++
		}
		shift := s.Sub(t.Start)
		for _, pi := range t.Packets {
			out[pi].Timestamp = pkts[pi].Timestamp.Add(shift)
		}
		connEnd[k] = t.End.Add(shift)
	}
	SortByTime(out)
	return out, Change{Transform: "retime", Params: map[string]any{"client": c.Client.String(), "server": c.Server.String(), "port": c.Port},
		In: len(pkts), Out: len(out), Changed: len(txns), Detail: fmt.Sprintf("%d transactions re-scheduled, %d pushed past the previous one on their connection", len(txns), pushed)}, nil
}

// Retime re-schedules channel c's transactions to a synth timing model
// (plus artifacts). The first transaction keeps its time; later ones
// follow the model's gaps. Events beyond the transaction count are unused.
func Retime(pkts []Packet, c Channel, m synth.Timing, a synth.Artifacts, seed uint64) ([]Packet, Change, error) {
	txns := Transactions(pkts, c)
	if len(txns) == 0 {
		return nil, Change{}, fmt.Errorf("retime: no transactions on %v → %v:%d", c.Client, c.Server, c.Port)
	}
	m.Events = len(txns)
	if err := m.Validate(); err != nil {
		return nil, Change{}, err
	}
	ev := synth.Schedule(txns[0].Start, m, a, rand.New(rand.NewPCG(seed, seed^0x51)))
	if len(ev) < len(txns) {
		return nil, Change{}, fmt.Errorf("retime: model produced %d events for %d transactions", len(ev), len(txns))
	}
	starts := make([]time.Time, len(txns))
	for i := range starts {
		starts[i] = txns[0].Start.Add(ev[i].At.Sub(ev[0].At))
	}
	out, ch, err := RetimeTo(pkts, c, starts)
	if err == nil {
		ch.Params["model"], ch.Params["sleep"], ch.Params["jitter"], ch.Params["seed"] = m.Model, m.Sleep, m.Jitter, seed
	}
	return out, ch, err
}
