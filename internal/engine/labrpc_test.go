package engine

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// v10a 2.1 lab gate: raw-TCP rpc_calls match the expected list (v7 prompt
// P1.8) exactly, nothing on any lab capture is called DCSync, and no
// lateral finding reaches 0.4 (the FP budget in TestCapture* covers that).
//
// One change from the v7 list, from the review-first read: "lsarpc opnum 77"
// is now named — v10a adds the MS-LSAT opnum table, where 77 is
// LsarLookupNames4.
func TestCaptureRPCCallsTCP(t *testing.T) {
	want := map[string]map[string]int{ // capture → "endpoint:op" → count (-1: any)
		"http_c2_enum": {},
		"part2": {"epmapper:ept_map": 2, "drsuapi:DRSBind": -1, "drsuapi:DRSUnbind": -1, "drsuapi:DRSCrackNames": -1,
			"netlogon:NetrLogonGetDomainInfo": -1},
		"smb2-wks":  {"epmapper:ept_map": 1, "lsarpc:LsarLookupNames4": 2},
		"smb2-data": {"drsuapi:DRSReplicaSync": 9, "unbound:opnum_3": 13},
	}
	for capName, exp := range want {
		t.Run(capName, func(t *testing.T) {
			for _, e := range engines {
				res := analyzeCapture(t, capName, e.cfg)
				got := map[string]int{}
				var rows []string
				for _, r := range res.RPCCalls {
					if r.Transport != "tcp" {
						continue
					}
					got[r.Endpoint+":"+r.Op] += r.Count
					rows = append(rows, fmt.Sprintf("%s→%s %s:%s ×%d ports=%v bound=%v learned=%s auth=%s", r.Client, r.Server, r.Endpoint, r.Op, r.Count, r.Ports, r.Bound, r.Learned, r.AuthLevel))
				}
				sort.Strings(rows)
				for k, n := range exp {
					if g, ok := got[k]; !ok || (n >= 0 && g != n) {
						t.Errorf("%s: %s ×%d, want ×%d\n  tcp rows:\n  %s", e.name, k, g, n, strings.Join(rows, "\n  "))
					}
				}
				for k := range got {
					if _, ok := exp[k]; !ok {
						t.Errorf("%s: unexpected tcp row %s\n  tcp rows:\n  %s", e.name, k, strings.Join(rows, "\n  "))
					}
				}
				for _, f := range res.Findings {
					if hasSignal(&f, "dcsync_from_non_dc") {
						t.Errorf("%s: DCSync on lab traffic: %s %+v", e.name, f.Title, f.Signals)
					}
					if f.Category == CatLateral && f.Score >= 0.4 {
						t.Errorf("%s: lateral finding %.2f %s", e.name, f.Score, f.Title)
					}
				}
			}
		})
	}
}
