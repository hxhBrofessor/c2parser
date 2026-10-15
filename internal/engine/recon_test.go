package engine

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"c2parser/internal/pcapio"
	mrand "math/rand/v2"
	"strings"
	"testing"
	"time"

	sy "c2parser/internal/synth"
)

// ---------------------------------------------------------------- fixtures

// httpBeacon writes a 30-check-in HTTP beacon from cli (a CatC2 finding
// ≥ 0.65, as in TestHTTPReassemblyChunkedAndBeacon) and returns the time
// after it.
func httpBeacon(s *synth, ts time.Time, cli, srv string) time.Time {
	r := mrand.New(mrand.NewPCG(3, 4))
	sess := s.tcp(ts, cli, 51000, srv, 80)
	for i := 0; i < 30; i++ {
		ts = ts.Add(time.Duration((5 + 0.3*(r.Float64()*2-1)) * float64(time.Second)))
		body := randB(600)
		hdr := fmt.Sprintf("POST /api/v1/sync HTTP/1.1\r\nHost: cdn-sync.example\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", len(body))
		sess.Send(ts, true, append([]byte(hdr), body...), 1400)
		resp := randB(300)
		sess.Send(ts.Add(40*time.Millisecond), false, append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", len(resp))), resp...), 1400)
	}
	sess.Close(ts.Add(time.Second))
	return ts.Add(2 * time.Second)
}

// ldapQuery is one search and the number of entries the server returns.
type ldapQuery struct {
	base    string
	scope   int
	filter  []byte
	attrs   []string
	entries int
	pages   int // extra follow-up pages (paged control with a cookie)
	ctls    [][]byte
}

// wrap is how messages go on the wire (plain, NTLM-signed, Kerberos).
type ldapWrap func(msg []byte, client bool) []byte

func plainLDAP(m []byte, _ bool) []byte { return m }
func ntlmLDAP(m []byte, _ bool) []byte  { return sy.SASLNTLM(m, 1) }
func krbLDAP(sealed bool) ldapWrap {
	return func(m []byte, _ bool) []byte { return sy.SASLKrb(m, sealed) }
}

// krbRRC is the Windows form: AcceptorSubkey (0x04) on client tokens,
// plus SentByAcceptor (0x01) on server tokens, 0x02 when sealed, and the
// checksum rotated to the front by rrc (Windows: RRC = EC = 12).
func krbRRC(sealed bool, rrc int) ldapWrap {
	return func(m []byte, client bool) []byte {
		f := byte(0x04)
		if !client {
			f |= 0x01
		}
		if sealed {
			f |= 0x02
		}
		return sy.SASLKrbWrap(m, f, rrc)
	}
}

func ldapSessionFx(s *synth, ts time.Time, cli string, cport uint16, dc string, wrap ldapWrap, qs ...ldapQuery) time.Time {
	c := s.tcp(ts, cli, cport, dc, 389)
	ts = c.Send(ts.Add(2*time.Millisecond), true, sy.LDAPBind(1), 1400)
	id := 2
	for _, q := range qs {
		for p := 0; p <= q.pages; p++ {
			ctls := append([][]byte(nil), q.ctls...)
			if q.pages > 0 {
				var cookie []byte
				if p > 0 {
					cookie = []byte{byte(p), 0xaa}
				}
				ctls = append(ctls, sy.PagedControl(500, cookie))
			}
			ts = c.Send(ts.Add(3*time.Millisecond), true, wrap(sy.LDAPSearch(id, q.base, q.scope, q.filter, q.attrs, ctls...), true), 1400)
			var resp []byte
			for i := 0; i < q.entries; i++ {
				resp = append(resp, wrap(sy.LDAPEntry(id, fmt.Sprintf("CN=obj%d,DC=corp,DC=example", i)), false)...)
			}
			resp = append(resp, wrap(sy.LDAPDone(id), false)...)
			ts = c.Send(ts.Add(2*time.Millisecond), false, resp, 1400)
			id++
		}
	}
	c.Close(ts.Add(5 * time.Millisecond))
	return ts.Add(10 * time.Millisecond)
}

const reconBase = "DC=corp,DC=example"

// attackQueries are the shapes AD-recon tooling sends (filters written
// from the published LDAP semantics, not copied from any tool).
func attackQueries() []ldapQuery {
	return []ldapQuery{
		{reconBase, 2, sy.FAnd(sy.FEq("objectCategory", "computer"), sy.FBitAnd("userAccountControl", 524288)), []string{"dNSHostName"}, 3, 0, nil},
		{reconBase, 2, sy.FAnd(sy.FEq("objectCategory", "person"), sy.FPresent("servicePrincipalName")), []string{"sAMAccountName", "servicePrincipalName"}, 12, 0, nil},
		{reconBase, 2, sy.FPresent("objectClass"), []string{"nTSecurityDescriptor"}, 400, 3, [][]byte{sy.SDFlagsControl()}},
	}
}

// benignLogonQueries: a domain-joined workstation's logon and GPO
// processing — rootDSE, its own computer object, gPLink/gPOptions on the
// OU chain, the GPO containers by DN.
func benignLogonQueries() []ldapQuery {
	return []ldapQuery{
		{"", 0, sy.FPresent("objectClass"), []string{"defaultNamingContext", "dnsHostName", "supportedCapabilities"}, 1, 0, nil},
		{reconBase, 2, sy.FAnd(sy.FEq("objectCategory", "computer"), sy.FEq("sAMAccountName", "WS01$")), []string{"distinguishedName", "userAccountControl"}, 1, 0, nil},
		{"OU=Workstations," + reconBase, 0, sy.FPresent("objectClass"), []string{"gPLink", "gPOptions"}, 1, 0, nil},
		{reconBase, 0, sy.FPresent("objectClass"), []string{"gPLink", "gPOptions"}, 1, 0, nil},
		{"CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System," + reconBase, 0, sy.FPresent("objectClass"), []string{"gPCFileSysPath", "versionNumber", "flags"}, 1, 0, nil},
		{reconBase, 2, sy.FAnd(sy.FEq("objectCategory", "person"), sy.FEq("sAMAccountName", "alice")), []string{"memberOf", "userAccountControl"}, 1, 0, nil},
		{"CN=Partitions,CN=Configuration," + reconBase, 1, sy.FAnd(sy.FEq("objectClass", "crossRef"), sy.FPresent("nETBIOSName")), []string{"nETBIOSName"}, 1, 0, nil},
	}
}

func reconFindings(res *Result) []*Finding {
	var out []*Finding
	for i := range res.Findings {
		if res.Findings[i].Category == CatRecon {
			out = append(out, &res.Findings[i])
		}
	}
	return out
}

func reconSig(f *Finding, name string) (float64, bool) {
	if s := signalOf(f, name); s != nil {
		return s.Score, true
	}
	return 0, false
}

func hasEvidence(f *Finding, sub string) bool {
	for _, e := range f.Evidence {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- tests

// From a host with a C2 finding ≥ 0.6, attack-shaped LDAP joins that
// finding as recon_from_c2_host with the filters as evidence, and makes
// no separate recon finding. Mutation: with reconC2 off the same traffic
// becomes a standalone finding and the C2 finding loses the signal.
func TestReconJoinsC2Finding(t *testing.T) {
	run := func() *Result {
		s := newSynth(t)
		ts := httpBeacon(s, s.now, "10.30.0.5", "203.0.113.60")
		ldapSessionFx(s, ts, "10.30.0.5", 50200, "10.30.0.10", plainLDAP, attackQueries()...)
		return s.analyze(Config{})
	}
	res := run()
	c2 := findBy(res, CatC2, "203.0.113.60")
	if c2 == nil {
		t.Fatalf("no C2 finding: %+v", res.Findings)
	}
	sc, ok := reconSig(c2, "recon_from_c2_host")
	if !ok || sc < 0.5 {
		t.Fatalf("recon_from_c2_host missing/weak (%v %.2f): %+v", ok, sc, c2.Signals)
	}
	for _, want := range []string{"TRUSTED_FOR_DELEGATION", "servicePrincipalName=*", "SD_FLAGS"} {
		if !hasEvidence(c2, want) {
			t.Errorf("evidence lacks %q: %v", want, c2.Evidence)
		}
	}
	if !hasEvidence(c2, "(userAccountControl:1.2.840.113556.1.4.803:=524288)") {
		t.Errorf("filter text not rendered in evidence: %v", c2.Evidence)
	}
	if r := reconFindings(res); len(r) != 0 {
		t.Errorf("recon from a C2 host also made a standalone finding: %+v", r)
	}

	reconC2 = false
	defer func() { reconC2 = true }()
	res = run()
	if c2 := findBy(res, CatC2, "203.0.113.60"); c2 != nil {
		if _, ok := reconSig(c2, "recon_from_c2_host"); ok {
			t.Error("mutation: recon still joined with reconC2 off")
		}
	}
	if r := reconFindings(res); len(r) != 1 {
		t.Errorf("mutation: want a standalone recon finding, got %+v", r)
	}
}

// From a host with no C2 finding the same recon is a standalone finding
// capped at medium, whatever the signals add up to.
func TestReconStandaloneCapped(t *testing.T) {
	s := newSynth(t)
	qs := append(attackQueries(),
		ldapQuery{reconBase, 2, sy.FAnd(sy.FEq("objectCategory", "person"), sy.FBitAnd("userAccountControl", 4194304)), []string{"sAMAccountName"}, 2, 0, nil},
		ldapQuery{reconBase, 2, sy.FEq("adminCount", "1"), []string{"sAMAccountName"}, 9, 0, nil},
		ldapQuery{"CN=Computers," + reconBase, 2, sy.FPresent("ms-Mcs-AdmPwd"), []string{"ms-Mcs-AdmPwd"}, 4, 0, nil},
	)
	ldapSessionFx(s, s.now, "10.30.0.6", 50201, "10.30.0.10", plainLDAP, qs...)
	res := s.analyze(Config{})
	r := reconFindings(res)
	if len(r) != 1 {
		t.Fatalf("want 1 recon finding, got %+v", res.Findings)
	}
	f := r[0]
	if f.Score > reconMax+1e-9 || f.Score < 0.4 {
		t.Errorf("standalone recon score %.3f, want medium (0.4–%.2f)", f.Score, reconMax)
	}
	for _, sig := range []string{"ldap_uac_delegation", "ldap_uac_asrep", "ldap_spn_enum", "ldap_acl_collection", "ldap_admincount", "ldap_laps_read", "ldap_bulk_enum"} {
		if _, ok := reconSig(f, sig); !ok {
			t.Errorf("missing %s: %+v", sig, f.Signals)
		}
	}
	if !hasEvidence(f, "capped at medium") {
		t.Errorf("cap not explained: %v", f.Evidence)
	}
	if f.Client != "10.30.0.6" || f.Server != "10.30.0.10" {
		t.Errorf("endpoints %s → %s", f.Client, f.Server)
	}
}

// v10a 2.2 synthetic gate: a domain-join logon (rootDSE, own computer
// object, gPLink, GPO containers, user lookup by name) makes no recon.
func TestReconBenignLogon(t *testing.T) {
	for _, w := range []struct {
		name string
		wrap ldapWrap
	}{{"plain", plainLDAP}, {"ntlm", ntlmLDAP}, {"krb", krbLDAP(false)}} {
		s := newSynth(t)
		ts := s.now
		for i := 0; i < 5; i++ { // several logons through the day
			ts = ldapSessionFx(s, ts.Add(time.Hour), "10.30.0.7", uint16(50300+i), "10.30.0.10", w.wrap, benignLogonQueries()...)
		}
		res := s.analyze(Config{})
		if r := reconFindings(res); len(r) != 0 {
			t.Errorf("%s: benign logon scored as recon: %+v", w.name, r[0])
		}
	}
}

// SASL: NTLM-signed and Kerberos integrity-only wraps are parsed; sealed
// Kerberos gives volume only (no searches, no recon).
func TestReconSASLWraps(t *testing.T) {
	for _, c := range []struct {
		name  string
		wrap  ldapWrap
		recon bool
	}{
		{"ntlm-signed", ntlmLDAP, true}, {"krb-integrity", krbLDAP(false), true}, {"krb-sealed", krbLDAP(true), false},
		// v10a.1: Windows default signing (lab http_c2_enum): RRC = EC = 12
		{"krb-signed-rrc12", krbRRC(false, 12), true}, {"krb-sealed-rrc12", krbRRC(true, 12), false},
		{"krb-signed-rrc0-subkey", krbRRC(false, 0), true}, {"krb-signed-rrc>len", krbRRC(false, 65535), true},
	} {
		s := newSynth(t)
		ldapSessionFx(s, s.now, "10.30.0.8", 50400, "10.30.0.10", c.wrap, attackQueries()...)
		e := New(Config{})
		res := analyzeEngine(t, s, e)
		got := len(reconFindings(res)) == 1
		if got != c.recon {
			t.Errorf("%s: recon finding %v, want %v (%+v)", c.name, got, c.recon, res.Findings)
		}
		if len(e.ldapSessions) != 1 {
			t.Fatalf("%s: %d LDAP sessions", c.name, len(e.ldapSessions))
		}
		ls := e.ldapSessions[0]
		if c.recon && len(ls.order) != 3 {
			t.Errorf("%s: %d searches parsed, want 3", c.name, len(ls.order))
		}
		if !c.recon && (!ls.sealed || ls.sealedB == 0 || len(ls.order) != 0) {
			t.Errorf("%s: sealed=%v bytes=%d searches=%d", c.name, ls.sealed, ls.sealedB, len(ls.order))
		}
	}
}

func presetQueries(t *testing.T, name string) []ldapQuery {
	qs, err := sy.LDAPPreset(name, reconBase, "WS01")
	if err != nil {
		t.Fatal(err)
	}
	var out []ldapQuery
	for _, q := range qs {
		out = append(out, ldapQuery{q.Base, q.Scope, q.Filter, q.Attrs, q.Entries, q.Pages, q.Ctls})
	}
	return out
}

// v10a.1: per-object ACL collection (the lab Havoc host's shape: a user
// dump, then each account's security descriptor read one at a time) →
// ldap_acl_sweep, plus ldap_bulk_enum for the completed user dump in a
// small domain. Mutation: an unreachable threshold loses the sweep.
func TestReconACLSweep(t *testing.T) {
	run := func() *Finding {
		s := newSynth(t)
		ldapSessionFx(s, s.now, "10.30.0.20", 50700, "10.30.0.10", krbRRC(false, 12), presetQueries(t, "acl-sweep")...)
		r := reconFindings(s.analyze(Config{}))
		if len(r) == 0 {
			return nil
		}
		return r[0]
	}
	f := run()
	if f == nil || !hasSignal(f, "ldap_acl_sweep") || !hasSignal(f, "ldap_bulk_enum") || f.Score > reconMax {
		t.Fatalf("acl sweep: %+v", f)
	}
	if s := signalOf(f, "ldap_acl_sweep"); !strings.Contains(s.Detail, "15 distinct account objects") {
		t.Errorf("detail: %s", s.Detail)
	}
	aclSweepMin = 1 << 30
	defer func() { aclSweepMin = 10 }()
	if f := run(); f != nil && hasSignal(f, "ldap_acl_sweep") {
		t.Error("mutation: sweep still found with an unreachable threshold")
	}
}

// The sweep window: 6 + 6 reads in two sessions 5 min apart is one sweep;
// 30 min apart it is not.
func TestReconACLSweepWindow(t *testing.T) {
	half := func(from int) []ldapQuery {
		var qs []ldapQuery
		for i := from; i < from+6; i++ {
			qs = append(qs, ldapQuery{fmt.Sprintf("CN=u%02d,CN=Users,%s", i, reconBase), 0, sy.FPresent("objectClass"), []string{"nTSecurityDescriptor"}, 1, 0, [][]byte{sy.SDFlagsControl()}})
		}
		return qs
	}
	for _, c := range []struct {
		gap  time.Duration
		want bool
	}{{5 * time.Minute, true}, {30 * time.Minute, false}} {
		s := newSynth(t)
		ts := ldapSessionFx(s, s.now, "10.30.0.21", 50710, "10.30.0.10", plainLDAP, half(0)...)
		ldapSessionFx(s, ts.Add(c.gap), "10.30.0.21", 50711, "10.30.0.10", plainLDAP, half(6)...)
		got := false
		for _, f := range reconFindings(s.analyze(Config{})) {
			got = got || hasSignal(f, "ldap_acl_sweep")
		}
		if got != c.want {
			t.Errorf("gap %s: sweep %v, want %v", c.gap, got, c.want)
		}
	}
}

// ADUC browsing (one-level OU listings, four Security tabs) is not recon.
// Own computer object, GPO containers and DCs never count toward a sweep.
func TestReconACLSweepBenign(t *testing.T) {
	s := newSynth(t)
	ldapSessionFx(s, s.now, "10.30.0.22", 50720, "10.30.0.10", plainLDAP, presetQueries(t, "aduc")...)
	if r := reconFindings(s.analyze(Config{})); len(r) != 0 {
		t.Errorf("ADUC browsing scored: %+v", r[0])
	}
	own := map[string]bool{"cn=ws01": true}
	for dn, want := range map[string]bool{
		"cn=alice,cn=users,dc=corp,dc=example": true, "cn=ws01,ou=workstations,dc=corp,dc=example": false,
		"cn={31b2f340-016d-11d2-945f-00c04fb984f9},cn=policies,cn=system,dc=corp,dc=example": false,
		"dc=corp,dc=example": false, "ou=staff,dc=corp,dc=example": false, "cn=x,cn=schema,cn=configuration,dc=corp,dc=example": false,
	} {
		if accountDN(dn, own) != want {
			t.Errorf("accountDN(%q) = %v", dn, !want)
		}
	}
}

// Whole-set bulk rule: a completed broad user search counts below 50
// entries; one cut short by the size limit (resultCode 4) does not.
func TestReconBulkWholeSet(t *testing.T) {
	for _, c := range []struct {
		code int
		want bool
	}{{0, true}, {4, false}} {
		s := newSynth(t)
		conn := s.tcp(s.now, "10.30.0.23", 50730, "10.30.0.10", 389)
		ts := conn.Send(s.now.Add(time.Millisecond), true, sy.LDAPSearch(2, reconBase, 2, sy.FEq("objectCategory", "user"), []string{"cn"}), 1400)
		var resp []byte
		for i := 0; i < 12; i++ {
			resp = append(resp, sy.LDAPEntry(2, fmt.Sprintf("CN=u%d,%s", i, reconBase))...)
		}
		resp = append(resp, sy.LDAPDoneCode(2, c.code)...)
		conn.Close(conn.Send(ts.Add(time.Millisecond), false, resp, 1400).Add(time.Millisecond))
		got := false
		for _, f := range reconFindings(s.analyze(Config{})) {
			got = got || hasSignal(f, "ldap_bulk_enum")
		}
		if got != c.want {
			t.Errorf("resultCode %d: bulk %v, want %v", c.code, got, c.want)
		}
	}
}

// v10a.1 mutation: without undoing the rotation, Windows-signed LDAP
// reads as sealed volume only (the v10a lab bug).
func TestReconRRCMutation(t *testing.T) {
	undoRRC = false
	defer func() { undoRRC = true }()
	s := newSynth(t)
	ldapSessionFx(s, s.now, "10.30.0.8", 50401, "10.30.0.10", krbRRC(false, 12), attackQueries()...)
	e := New(Config{})
	res := analyzeEngine(t, s, e)
	ls := e.ldapSessions[0]
	if len(reconFindings(res)) != 0 || len(ls.order) != 0 || !ls.sealed {
		t.Errorf("mutation: rotated tokens still parsed (searches %d, sealed %v)", len(ls.order), ls.sealed)
	}
}

// Narrowed and base-scope queries are routine even with attack-ish
// attributes; a single-object SPN read by name is not Kerberoasting.
func TestReconNotScored(t *testing.T) {
	s := newSynth(t)
	ldapSessionFx(s, s.now, "10.30.0.9", 50500, "10.30.0.10", plainLDAP,
		ldapQuery{reconBase, 2, sy.FAnd(sy.FEq("sAMAccountName", "svc_sql"), sy.FPresent("servicePrincipalName")), []string{"servicePrincipalName"}, 1, 0, nil},
		ldapQuery{"CN=WS01,OU=Workstations," + reconBase, 0, sy.FPresent("objectClass"), []string{"nTSecurityDescriptor"}, 1, 0, [][]byte{sy.SDFlagsControl()}},
		ldapQuery{reconBase, 2, sy.FAnd(sy.FEq("objectCategory", "person"), sy.FSub("sAMAccountName", "ali")), []string{"cn"}, 3, 0, nil},
		ldapQuery{reconBase, 2, sy.FEq("objectCategory", "group"), []string{"cn"}, 20, 0, nil}, // < 50 entries, one page
	)
	res := s.analyze(Config{})
	if r := reconFindings(res); len(r) != 0 {
		t.Errorf("routine queries scored: %+v", r[0])
	}
}

// Recon from one DC to another is replication/management, never scored.
func TestReconDCToDC(t *testing.T) {
	s := newSynth(t)
	ts := ldapSessionFx(s, s.now, "10.30.0.11", 50600, "10.30.0.10", plainLDAP, attackQueries()...)
	_ = ts
	res := s.analyze(Config{DCs: mustAddrs("10.30.0.11", "10.30.0.10")})
	if r := reconFindings(res); len(r) != 0 {
		t.Errorf("DC→DC LDAP scored: %+v", r[0])
	}
}

// samr enumeration over \PIPE\samr is recon; MS-TSTS session enumeration
// alone is low and stays below medium.
func TestReconSAMRAndTSTS(t *testing.T) {
	s := newSynth(t)
	const uuidSAMR = "12345778-1234-abcd-ef00-0123456789ac"
	smbPipeSession(t, s, "10.30.0.12", "10.30.0.10", "samr",
		dceBind(t, 0, uuidSAMR),
		dceRequest(0, 13, randB(24)), // SamrEnumerateUsersInDomain
		dceRequest(0, 33, randB(24)), // SamrGetMembersInAlias
	)
	res := s.analyze(Config{})
	r := reconFindings(res)
	if len(r) != 1 {
		t.Fatalf("samr enumeration: want 1 recon finding, got %+v", res.Findings)
	}
	if _, ok := reconSig(r[0], "samr_enumeration"); !ok || r[0].Score > reconMax {
		t.Errorf("samr: %+v score %.2f", r[0].Signals, r[0].Score)
	}

	s = newSynth(t)
	const uuidTermSrvEnum = "88143fd0-c28d-4b2b-8fef-8d882f6a9390"
	smbPipeSession(t, s, "10.30.0.13", "10.30.0.10", "LSM_API_service",
		dceBind(t, 0, uuidTermSrvEnum),
		dceRequest(0, 1, randB(24)),
	)
	res = s.analyze(Config{})
	for _, f := range reconFindings(res) {
		if f.Score >= 0.4 {
			t.Errorf("TSTS alone reached %.2f", f.Score)
		}
	}
}

// ---------------------------------------------------------------- fuzz

func FuzzLDAPMessage(f *testing.F) {
	for _, q := range append(attackQueries(), benignLogonQueries()...) {
		f.Add(sy.LDAPSearch(2, q.base, q.scope, q.filter, q.attrs, sy.PagedControl(500, []byte{1}), sy.SDFlagsControl()))
	}
	f.Add(sy.SASLNTLM(sy.LDAPSearch(3, "", 0, sy.FPresent("objectClass"), nil), 1))
	f.Add(sy.SASLKrb(sy.LDAPEntry(3, "CN=x"), false))
	f.Add(sy.SASLKrbWrap(sy.LDAPSearch(4, "DC=x", 2, sy.FPresent("objectClass"), nil, sy.SDFlagsControl()), 0x04, 12))
	f.Add(sy.SASLKrbWrap(sy.LDAPEntry(4, "CN=y"), 0x05, 12))
	f.Add(sy.SASLKrbWrap(sy.LDAPDone(4), 0x04, 65535))
	f.Add(sy.SASLKrbWrap(nil, 0x06, 12))
	f.Add([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x02, 0x01})
	f.Fuzz(func(t *testing.T, d []byte) {
		e := New(Config{})
		s := e.newLDAPSession(&tcpConn{ch: &channel{}})
		ts := time.Unix(0, 0)
		(&ldapHalf{e: e, s: s, client: true}).feed(d, ts, 1)
		(&ldapHalf{e: e, s: s}).feed(d, ts, 2)
		for _, sr := range s.searches() {
			ldapRecon(sr)
		}
		looksLDAP(d)
	})
}

func FuzzBER(f *testing.F) {
	f.Add(sy.FAnd(sy.FOr(sy.FNot(sy.FEq("a", "b")), sy.FSub("cn", "x")), sy.FBitAnd("userAccountControl", 4194304)))
	f.Add([]byte{0xa0, 0x82, 0x00})
	f.Fuzz(func(t *testing.T, d []byte) {
		berLen(d)
		if tlv, _, ok := berNext(d); ok {
			fx := ldapFacts{attrs: map[string]bool{}, present: map[string]bool{}, equals: map[string][]string{}}
			renderFilter(tlv, &fx, 0)
			berInt(tlv.val)
		}
		parseSearch(d)
		parseControls(d)
	})
}

func mustAddrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// analyzeEngine runs the synth pcap through a caller-held engine so the
// test can inspect its state after Finish.
func analyzeEngine(t *testing.T, s *synth, e *Engine) *Result {
	p := filepath.Join(t.TempDir(), "synth.pcap")
	if err := os.WriteFile(p, s.buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := pcapio.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := e.Ingest(r); err != nil {
		t.Fatal(err)
	}
	return e.Finish()
}
