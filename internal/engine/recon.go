package engine

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"c2parser/internal/stats"
)

// AD reconnaissance (v10a 2.2). LDAP searches with attack-shaped filters,
// samr account/group enumeration and MS-TSTS session enumeration are
// recon evidence. From a host that already has a C2 finding ≥ 0.6 they
// join that finding (recon_from_c2_host + the filters and ops as
// evidence); elsewhere they form a standalone recon finding capped at
// medium. Routine Windows LDAP is never scored: rootDSE, base-scope reads
// of single objects, GPO (gPLink/gPOptions) processing, lookups narrowed
// to one account, and anything between domain controllers.

const CatRecon = "AD reconnaissance"

// reconMax caps a standalone recon finding below high.
const reconMax = 0.64

// reconC2 enables joining recon to the host's C2 finding (mutation test).
var reconC2 = true

// gpoSDGuard excludes the Group Policy client's SD reads under
// CN=Policies,CN=System from ldap_acl_collection (v10b; mutation hook).
var gpoSDGuard = true

// reconJoinCapAware skips capped series when joining recon (mutation hook).
var reconJoinCapAware = true

// bulkMinEntries is ldap_bulk_enum's entry threshold for searches that did
// not complete in the capture.
const bulkMinEntries = 50

// aclSweepMin is how many distinct account objects must have their
// security descriptor read one at a time (base scope + SD_FLAGS) within
// aclSweepWindow for ldap_acl_sweep (v10a.1; mutation hook).
var aclSweepMin = 10

const aclSweepWindow = 10 * time.Minute

type reconHit struct {
	sig    stats.Signal
	ev     string // evidence line (the filter or op that produced it)
	server netip.Addr
	frame  int64
}

var privilegedGroups = []string{"domain admins", "enterprise admins", "schema admins", "key admins", "enterprise key admins",
	"dnsadmins", "administrators", "account operators", "backup operators", "server operators", "print operators", "group policy creator owners"}

var lapsAttrs = map[string]bool{"ms-mcs-admpwd": true, "ms-mcs-admpwdexpirationtime": true, "mslaps-password": true, "mslaps-encryptedpassword": true}
var delegationAttrs = map[string]bool{"msds-allowedtodelegateto": true, "msds-allowedtoactonbehalfofotheridentity": true}

func hasAttr(list []string, set map[string]bool) string {
	for _, a := range list {
		if set[strings.ToLower(a)] {
			return a
		}
	}
	return ""
}

// ldapRecon turns one search into recon hits (none for routine queries).
func ldapRecon(s *ldapSearch) []reconHit {
	f := &s.facts
	var out []reconHit
	add := func(name string, w float64, what string) {
		out = append(out, reconHit{sig: stats.Signal{Name: name, Weight: w, Score: 1,
			Detail: fmt.Sprintf("%s: base %q scope %d filter %s (×%d, %d entries returned)", what, s.base, s.scope, s.filter, s.count, s.entries)}})
	}
	// reads that matter even on one object
	if a := hasAttr(s.attrs, lapsAttrs); a != "" || hasAttrSet(f.attrs, lapsAttrs) {
		add("ldap_laps_read", 0.5, "LAPS password attribute requested")
	}
	sdFlags := false
	for _, c := range s.controls {
		if c == oidSDFlags {
			sdFlags = true
		}
	}
	wantsSD := hasAttr(s.attrs, map[string]bool{"ntsecuritydescriptor": true}) != ""
	if s.scope == 0 { // base scope: rootDSE, GPO links, one object — routine
		return out
	}
	// the Group Policy client reads GPO security descriptors (SD_FLAGS) under
	// CN=Policies,CN=System on every refresh — routine, not ACL collection
	if wantsSD && sdFlags && !(gpoSDGuard && strings.Contains(strings.ToLower(s.base), "cn=policies,cn=system")) {
		add("ldap_acl_collection", 0.45, "security descriptors collected with the SD_FLAGS control (ACL enumeration)")
	}
	for _, bit := range f.uacBits {
		switch {
		case bit&524288 != 0:
			add("ldap_uac_delegation", 0.5, "userAccountControl TRUSTED_FOR_DELEGATION bit test (unconstrained-delegation hunt)")
		case bit&16777216 != 0:
			add("ldap_uac_delegation", 0.5, "userAccountControl TRUSTED_TO_AUTH_FOR_DELEGATION bit test (constrained-delegation hunt)")
		case bit&4194304 != 0:
			add("ldap_uac_asrep", 0.5, "userAccountControl DONT_REQ_PREAUTH bit test (AS-REP roasting hunt)")
		}
	}
	if f.present["serviceprincipalname"] && !f.narrowed {
		add("ldap_spn_enum", 0.45, "servicePrincipalName=* across accounts (Kerberoasting hunt)")
	}
	if a := hasAttr(s.attrs, delegationAttrs); a != "" || hasAttrSet(f.attrs, delegationAttrs) {
		add("ldap_delegation_attrs", 0.45, "delegation attributes queried")
	}
	for _, v := range f.equals["admincount"] {
		if v == "1" {
			add("ldap_admincount", 0.4, "adminCount=1 (protected/privileged accounts)")
		}
	}
	lf := strings.ToLower(s.filter)
	for _, g := range privilegedGroups {
		if strings.Contains(lf, "="+g+")") || strings.Contains(lf, "cn="+g+",") {
			add("ldap_privileged_group_enum", 0.35, "privileged group enumerated")
			break
		}
	}
	broad := !f.narrowed
	objType, users := false, false
	for _, c := range f.classes {
		switch c {
		case "person", "user", "computer", "group", "*":
			objType = true
		}
		users = users || c == "person" || c == "user"
	}
	// "the whole set" only for a bare class filter: no predicate besides
	// objectClass / objectCategory (an AS-REP bit test returning two
	// accounts is not a dump of every user)
	bare := f.extensible == 0
	for a := range f.attrs {
		if a != "objectclass" && a != "objectcategory" {
			bare = false
		}
	}
	// bulk: ≥ 50 entries or ≥ 2 pages; for user objects ≥ min(50, the
	// whole set) — a completed broad user search returned every account, so
	// a small domain's full user dump counts too (v10a.1)
	if broad && (objType || (f.present["objectclass"] && len(f.attrs) == 1)) && s.scope == 2 &&
		(s.entries >= bulkMinEntries || s.pages >= 2 || users && bare && s.completed && s.entries > 0) {
		add("ldap_bulk_enum", 0.35, "bulk subtree enumeration of users/computers/groups")
	}
	return out
}

func hasAttrSet(m map[string]bool, set map[string]bool) bool {
	for a := range m {
		if set[a] {
			return true
		}
	}
	return false
}

// samrRecon are the samr operations that enumerate accounts and groups.
var samrRecon = map[string]bool{"SamrEnumerateUsersInDomain": true, "SamrEnumerateGroupsInDomain": true, "SamrEnumerateAliasesInDomain": true,
	"SamrGetMembersInAlias": true, "SamrGetMembersInGroup": true, "SamrGetGroupsForUser": true, "SamrQueryDisplayInformation": true,
	"SamrQueryDisplayInformation2": true, "SamrQueryDisplayInformation3": true, "SamrGetAliasMembership": true}

// scoreRecon runs after correlation: it needs the C2 findings' scores.
func (e *Engine) scoreRecon(sc *scorer, cad *cadence) {
	assocs := e.rpcAssocs()
	dcs := e.dcHosts(assocs)
	hits := map[netip.Addr][]reconHit{}
	var clients []netip.Addr
	addHit := func(cl netip.Addr, h reconHit) {
		if _, ok := hits[cl]; !ok {
			clients = append(clients, cl)
		}
		hits[cl] = append(hits[cl], h)
	}
	for _, s := range e.ldapSessions {
		cl := s.c.client.Addr()
		if dcs[cl] {
			continue // DC ↔ DC
		}
		for _, sr := range s.searches() {
			for _, h := range ldapRecon(sr) {
				h.server, h.frame = s.c.server.Addr(), sr.frame
				addHit(cl, h)
			}
		}
	}
	for _, h := range e.aclSweeps(dcs) {
		addHit(h.client, h.hit)
	}
	pipeServers := map[string]bool{}
	for _, k := range sc.order {
		if a := sc.accs[k]; a.f.Category == CatPipe {
			pipeServers[a.f.Server] = true
		}
	}
	for _, as := range assocs {
		cl := as.client.Addr()
		if dcs[cl] {
			continue
		}
		keys := make([]string, 0, len(as.st.calls))
		for k := range as.st.calls {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			ep, op, _ := strings.Cut(k, ":")
			n := as.st.calls[k]
			switch {
			case ep == "samr" && samrRecon[op]:
				addHit(cl, reconHit{sig: stats.Signal{Name: "samr_enumeration", Weight: 0.4, Score: 1,
					Detail: fmt.Sprintf("samr %s ×%d to %s", op, n, as.server.Addr())}, server: as.server.Addr(), frame: as.firstFrame})
			case strings.HasPrefix(ep, "TermSrv") || strings.HasPrefix(ep, "RCM"):
				w := 0.15 // qwinsta /server and Server Manager do this too
				why := ""
				if pipeServers[cl.String()] {
					w, why = 0.3, " from a host that is itself a pivot-pipe target"
				}
				addHit(cl, reconHit{sig: stats.Signal{Name: "tsts_session_enum", Weight: w, Score: 1,
					Detail: fmt.Sprintf("MS-TSTS %s:%s ×%d to %s (session enumeration)%s", ep, op, n, as.server.Addr(), why)}, server: as.server.Addr(), frame: as.firstFrame})
			}
		}
	}
	// the host's strongest C2 finding (CatC2 or pivot pipe). A series the
	// fleet / poller / scheduler rules cap at 0.39 never qualifies: the
	// join reads the capped score (v10a.1 D3; the lab review found the
	// raw pre-cap score let a capped fleet member take recon and lose its
	// cap)
	c2 := map[string]*acc{}
	for _, k := range sc.order {
		a := sc.accs[k]
		if a.f.Category != CatC2 && a.f.Category != CatPipe {
			continue
		}
		if reconJoinCapAware && a.capped(e, cad) {
			continue
		}
		if s := a.score(); s >= 0.6 && (c2[a.f.Client] == nil || s > c2[a.f.Client].score()) {
			c2[a.f.Client] = a
		}
	}
	for _, cl := range clients {
		hs := hits[cl]
		// strongest per signal name; evidence lines in order seen
		best := map[string]stats.Signal{}
		var lines []string
		seenLine := map[string]bool{}
		servers := map[string]bool{}
		for _, h := range hs {
			if old, ok := best[h.sig.Name]; !ok || h.sig.Contribution() > old.Contribution() {
				best[h.sig.Name] = h.sig
			}
			if len(lines) < 8 && !seenLine[h.sig.Detail] { // the same query in each session reads once
				seenLine[h.sig.Detail] = true
				lines = append(lines, h.sig.Detail)
			}
			servers[h.server.String()] = true
		}
		var sigs []stats.Signal
		for _, s := range best {
			sigs = append(sigs, s)
		}
		stats.SortSignals(sigs)
		strength := stats.NoisyOR(sigs)
		if a := c2[cl.String()]; a != nil && reconC2 {
			names := make([]string, 0, len(sigs))
			for _, s := range sigs {
				names = append(names, s.Name)
			}
			a.add(stats.Signal{Name: "recon_from_c2_host", Weight: 0.5, Score: strength,
				Detail: fmt.Sprintf("AD reconnaissance from this host to %s: %s", strings.Join(sortedKeys(servers), ", "), strings.Join(names, ", "))})
			for _, l := range lines {
				a.evidence("AD recon: %s", l)
			}
			continue
		}
		srv := sortedKeys(servers)
		title := fmt.Sprintf("AD reconnaissance %s → %s", cl, strings.Join(srv, ", "))
		a := sc.get("recon|"+cl.String(), CatRecon, title, cl, mustAddr(srv[0]), timeZero, timeZero)
		for _, s := range sigs {
			a.add(s)
		}
		for _, h := range hs {
			a.frames(h.frame)
		}
		a.reconCap = true
	}
}

type sdRead struct {
	at     time.Time
	dn     string
	server netip.Addr
	frame  int64
}

type clientHit struct {
	client netip.Addr
	hit    reconHit
}

// aclSweeps finds per-object ACL collection: base-scope reads carrying the
// SD_FLAGS control on ≥ aclSweepMin distinct account DNs (first RDN CN=,
// outside Configuration/Schema/Policies, not the client's own computer
// object) from one client within aclSweepWindow, across its sessions.
// ADUC opening a few Security tabs stays well below the threshold.
func (e *Engine) aclSweeps(dcs map[netip.Addr]bool) []clientHit {
	reads := map[netip.Addr][]sdRead{}
	own := map[netip.Addr]map[string]bool{}
	var order []netip.Addr
	for _, s := range e.ldapSessions {
		cl := s.c.client.Addr()
		if dcs[cl] {
			continue
		}
		for _, sr := range s.searches() {
			for _, v := range sr.facts.equals["samaccountname"] {
				if strings.HasSuffix(v, "$") {
					if own[cl] == nil {
						own[cl] = map[string]bool{}
					}
					own[cl]["cn="+strings.ToLower(strings.TrimSuffix(v, "$"))] = true
				}
			}
			if sr.scope != 0 || !hasControl(sr.controls, oidSDFlags) {
				continue
			}
			if _, ok := reads[cl]; !ok {
				order = append(order, cl)
			}
			reads[cl] = append(reads[cl], sdRead{sr.first, strings.ToLower(sr.base), s.c.server.Addr(), sr.frame})
		}
	}
	var out []clientHit
	for _, cl := range order {
		rs := reads[cl]
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].at.Before(rs[j].at) })
		best, bestI, bestJ := 0, 0, 0
		for i := range rs {
			seen := map[string]bool{}
			for j := i; j < len(rs) && rs[j].at.Sub(rs[i].at) <= aclSweepWindow; j++ {
				if accountDN(rs[j].dn, own[cl]) {
					seen[rs[j].dn] = true
				}
				if len(seen) > best {
					best, bestI, bestJ = len(seen), i, j
				}
			}
		}
		if best < aclSweepMin {
			continue
		}
		span := rs[bestJ].at.Sub(rs[bestI].at).Round(time.Second)
		out = append(out, clientHit{cl, reconHit{sig: stats.Signal{Name: "ldap_acl_sweep", Weight: 0.5, Score: 1,
			Detail: fmt.Sprintf("security descriptors read one object at a time (base scope + SD_FLAGS) on %d distinct account objects within %s (per-object ACL collection), e.g. %q", best, span, rs[bestI].dn)},
			server: rs[bestI].server, frame: rs[bestI].frame}})
	}
	return out
}

func hasControl(ctls []string, oid string) bool {
	for _, c := range ctls {
		if c == oid {
			return true
		}
	}
	return false
}

// accountDN: a user/computer/trust-account-shaped DN (first RDN CN=),
// not configuration, schema or GPO containers, not the client's own object.
func accountDN(dn string, own map[string]bool) bool {
	if !strings.HasPrefix(dn, "cn=") || strings.Contains(dn, "cn=policies,cn=system") ||
		strings.Contains(dn, "cn=configuration,") || strings.Contains(dn, "cn=schema,") {
		return false
	}
	first, _, _ := strings.Cut(dn, ",")
	return !own[first]
}
