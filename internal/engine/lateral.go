package engine

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"c2parser/internal/stats"
)

// rpcAssoc is one DCE/RPC association: an SMB pipe (opens consolidated)
// or a raw-TCP connection (v10a 2.1).
type rpcAssoc struct {
	client, server netip.AddrPort
	pipe           string // smb-pipe
	st             *dceState
	first, last    time.Time
	firstFrame     int64
	users          []string
}

func (e *Engine) rpcAssocs() []rpcAssoc {
	var out []rpcAssoc
	for _, st := range e.smbStates {
		st.consolidate()
		users := sortedKeys(st.users)
		for _, f := range st.order {
			if f.dce != nil {
				out = append(out, rpcAssoc{client: st.c.client, server: st.c.server, pipe: f.pipeName(), st: f.dce,
					first: f.first, last: f.last, firstFrame: f.firstFrame, users: users})
			}
		}
	}
	for _, dc := range e.dceConns {
		if len(dc.st.calls) > 0 {
			out = append(out, rpcAssoc{client: dc.c.client, server: dc.c.server, st: dc.st, first: dc.c.start, last: dc.last, firstFrame: dc.c.firstFrame})
		}
	}
	return out
}

// dcGuard enables the DC-replication guard (a var for the mutation test).
var dcGuard = true

// dcHosts are domain controllers: declared with -dc, seen serving Kerberos
// (88) or LDAP (389), or answering drsuapi.
func (e *Engine) dcHosts(assocs []rpcAssoc) map[netip.Addr]bool {
	dc := map[netip.Addr]bool{}
	for _, a := range e.cfg.DCs {
		dc[a.Unmap()] = true
	}
	for _, ch := range e.chOrder {
		if ch.key.port == 88 || ch.key.port == 389 {
			dc[ch.key.server] = true
		}
	}
	for _, as := range assocs {
		for k := range as.st.calls {
			if strings.HasPrefix(k, "drsuapi:") {
				dc[as.server.Addr()] = true
			}
		}
	}
	return dc
}

// scoreLateral turns risky DCE/RPC operations into findings, over SMB pipes
// and raw TCP alike. drsuapi:DRSGetNCChanges goes through the DC guard:
// from a domain controller it is replication (an info note); from any
// other host it is dcsync_from_non_dc.
func (e *Engine) scoreLateral(sc *scorer) {
	assocs := e.rpcAssocs()
	dcs := e.dcHosts(assocs)
	for _, as := range assocs {
		keys := make([]string, 0, len(as.st.calls))
		for k := range as.st.calls {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		via := "via \\pipe\\" + as.pipe
		title := fmt.Sprintf("Remote execution over SMB %s → %s", as.client.Addr(), as.server.Addr())
		if as.st.transport == "tcp" {
			via = fmt.Sprintf("over DCE/RPC tcp/%d", as.server.Port())
			title = fmt.Sprintf("Remote execution over DCE/RPC tcp/%d %s → %s", as.server.Port(), as.client.Addr(), as.server.Addr())
		}
		key := "lateral|" + as.client.Addr().String() + "|" + as.server.Addr().String()
		for _, k := range keys {
			n := as.st.calls[k]
			if k == "drsuapi:DRSGetNCChanges" {
				if dcGuard && dcs[as.client.Addr()] {
					a := sc.get("dcrepl|"+as.client.Addr().String()+"|"+as.server.Addr().String(), CatDCRepl,
						fmt.Sprintf("DC replication %s → %s (drsuapi)", as.client.Addr(), as.server.Addr()), as.client.Addr(), as.server.Addr(), as.first, as.last)
					a.add(stats.Signal{Name: "dc_replication", Weight: 0.1, Score: 1,
						Detail: fmt.Sprintf("DRSGetNCChanges ×%d %s between domain controllers — normal replication, not DCSync", n, via)})
					a.frames(as.firstFrame)
					continue
				}
				a := sc.get(key, CatLateral, title, as.client.Addr(), as.server.Addr(), as.first, as.last)
				a.add(stats.Signal{Name: "dcsync_from_non_dc", Weight: 0.8, Score: 1,
					Detail: fmt.Sprintf("DRSGetNCChanges ×%d %s from %s, which is not a domain controller (not seen serving 88/389 or drsuapi, not in -dc) — DCSync", n, via, as.client.Addr())})
				a.frames(as.firstFrame)
				continue
			}
			risk, ok := rpcRisk[k]
			if !ok {
				continue
			}
			a := sc.get(key, CatLateral, title, as.client.Addr(), as.server.Addr(), as.first, as.last)
			a.add(stats.Signal{Name: "rpc:" + k, Weight: risk.w, Score: 1,
				Detail: fmt.Sprintf("%s ×%d %s — %s", k, n, via, risk.what)})
			if len(as.users) > 0 && len(a.f.Evidence) == 0 {
				a.evidence("SMB session authenticated as: %s", strings.Join(as.users, ", "))
			}
			a.frames(as.firstFrame)
		}
	}
}

// CatDCRepl is the info-level category for replication between DCs.
const CatDCRepl = "Directory replication (info)"
