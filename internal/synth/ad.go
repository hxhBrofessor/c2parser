package synth

import (
	"fmt"
	"time"
)

// Directory-service traffic presets for scenarios (v10a 2.2 / 2.1): LDAP
// sessions shaped like AD reconnaissance or like a workstation's logon and
// Group Policy processing, and raw-TCP DCE/RPC exchanges. Filters are
// written from the published LDAP/AD semantics, not copied from any tool.

// LDAPQuery is one search and the entries the server returns.
type LDAPQuery struct {
	Base    string
	Scope   int
	Filter  []byte
	Attrs   []string
	Entries int
	Pages   int // extra follow-up pages (paged control with a cookie)
	Ctls    [][]byte
}

// LDAPPreset returns the queries for a preset: "recon" (delegation,
// AS-REP and SPN hunts, ACL collection), "acl-sweep" (a user dump, then
// per-object security-descriptor reads, the shape seen from the lab's
// Havoc host), "aduc" (OU browsing plus four Security tabs) or "logon"
// (rootDSE, own objects, gPLink and GPO containers).
func LDAPPreset(name, base, host string) ([]LDAPQuery, error) {
	switch name {
	case "recon":
		return []LDAPQuery{
			{base, 2, FAnd(FEq("objectCategory", "computer"), FBitAnd("userAccountControl", 524288)), []string{"dNSHostName"}, 3, 0, nil},
			{base, 2, FAnd(FEq("objectCategory", "person"), FBitAnd("userAccountControl", 4194304)), []string{"sAMAccountName"}, 2, 0, nil},
			{base, 2, FAnd(FEq("objectCategory", "person"), FPresent("servicePrincipalName")), []string{"sAMAccountName", "servicePrincipalName"}, 12, 0, nil},
			{base, 2, FPresent("objectClass"), []string{"nTSecurityDescriptor"}, 400, 3, [][]byte{SDFlagsControl()}},
		}, nil
	case "acl-sweep": // one user dump, then each account's object and its security descriptor, one at a time
		qs := []LDAPQuery{{base, 2, FEq("objectCategory", "user"), []string{"distinguishedName"}, 15, 0, nil}}
		for i := 0; i < 15; i++ {
			dn := fmt.Sprintf("CN=user%02d,CN=Users,%s", i, base)
			qs = append(qs,
				LDAPQuery{dn, 0, FPresent("objectClass"), []string{"objectSid", "sAMAccountName"}, 1, 0, nil},
				LDAPQuery{dn, 0, FPresent("objectClass"), []string{"nTSecurityDescriptor"}, 1, 0, [][]byte{SDFlagsControl()}})
		}
		return qs, nil
	case "aduc": // an admin browsing two OUs and opening a few Security tabs
		qs := []LDAPQuery{
			{"OU=Staff," + base, 1, FPresent("objectClass"), []string{"name", "objectClass"}, 25, 0, nil},
			{"OU=Workstations," + base, 1, FPresent("objectClass"), []string{"name", "objectClass"}, 30, 0, nil},
		}
		for i := 0; i < 4; i++ {
			qs = append(qs, LDAPQuery{fmt.Sprintf("CN=staff%02d,OU=Staff,%s", i, base), 0, FPresent("objectClass"), []string{"nTSecurityDescriptor"}, 1, 0, [][]byte{SDFlagsControl()}})
		}
		return qs, nil
	case "logon", "":
		return []LDAPQuery{
			{"", 0, FPresent("objectClass"), []string{"defaultNamingContext", "dnsHostName", "supportedCapabilities"}, 1, 0, nil},
			{base, 2, FAnd(FEq("objectCategory", "computer"), FEq("sAMAccountName", host+"$")), []string{"distinguishedName", "userAccountControl"}, 1, 0, nil},
			{"OU=Workstations," + base, 0, FPresent("objectClass"), []string{"gPLink", "gPOptions"}, 1, 0, nil},
			{base, 0, FPresent("objectClass"), []string{"gPLink", "gPOptions"}, 1, 0, nil},
			{"CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System," + base, 0, FPresent("objectClass"), []string{"gPCFileSysPath", "versionNumber", "flags"}, 1, 0, nil},
			// the Group Policy client (gpsvc) checking access to each applicable
			// GPO: a subtree search under Policies for the GPO DNs, reading their
			// security descriptors with SD_FLAGS (machine and user extensions)
			GPOSecurityQuery(base, "gPCMachineExtensionNames"),
			GPOSecurityQuery(base, "gPCUserExtensionNames"),
			{"CN=Partitions,CN=Configuration," + base, 1, FAnd(FEq("objectClass", "crossRef"), FPresent("nETBIOSName")), []string{"nETBIOSName"}, 1, 0, nil},
		}, nil
	}
	return nil, fmt.Errorf("ldap preset %q: want recon, acl-sweep, aduc or logon", name)
}

// GPOSecurityQuery is the Group Policy client's per-refresh read of the
// applicable GPOs' security descriptors (the shape seen in the lab's part2
// capture): subtree under CN=Policies,CN=System, enabled GPOs with the
// given extension attribute, narrowed to the GPO DNs, nTSecurityDescriptor
// with SD_FLAGS.
func GPOSecurityQuery(base, ext string) LDAPQuery {
	pol := "CN=Policies,CN=System," + base
	gpos := FOr(FEq("distinguishedName", "CN={31B2F340-016D-11D2-945F-00C04FB984F9},"+pol), FEq("distinguishedName", "CN={6AC1786C-016F-11D2-945F-00C04FB984F9},"+pol))
	return LDAPQuery{pol, 2, FAnd(FNot(FBitAnd("flags", 1)), FPresent(ext), gpos),
		[]string{"nTSecurityDescriptor", "displayName", "gPCFileSysPath", "versionNumber", ext}, 2, 0, [][]byte{SDFlagsControl()}}
}

// LDAPSession writes one LDAP connection to dc:389: a SASL bind, then the
// queries with their entries and done messages.
func (b *Builder) LDAPSession(ts time.Time, cli string, cport uint16, dc string, qs []LDAPQuery) time.Time {
	return b.LDAPSessionSASL(ts, cli, cport, dc, "", qs)
}

// LDAPSessionSASL is LDAPSession with the post-bind messages wrapped:
// sasl "" (plain), "ntlm" (NTLM-signed) or "krb" (Kerberos-signed, the
// Windows default form: RRC = EC = 12, AcceptorSubkey).
func (b *Builder) LDAPSessionSASL(ts time.Time, cli string, cport uint16, dc, sasl string, qs []LDAPQuery) time.Time {
	wrap := func(m []byte, client bool) []byte {
		switch sasl {
		case "ntlm":
			return SASLNTLM(m, 1)
		case "krb":
			f := byte(0x04)
			if !client {
				f |= 0x01
			}
			return SASLKrbWrap(m, f, 12)
		}
		return m
	}
	c := b.TCP(ts, cli, cport, dc, 389)
	ts = c.Send(ts.Add(2*time.Millisecond), true, LDAPBind(1), 1400)
	id := 2
	for _, q := range qs {
		for p := 0; p <= q.Pages; p++ {
			ctls := append([][]byte(nil), q.Ctls...)
			if q.Pages > 0 {
				var cookie []byte
				if p > 0 {
					cookie = []byte{byte(p), 0xaa}
				}
				ctls = append(ctls, PagedControl(500, cookie))
			}
			ts = c.Send(ts.Add(3*time.Millisecond), true, wrap(LDAPSearch(id, q.Base, q.Scope, q.Filter, q.Attrs, ctls...), true), 1400)
			var resp []byte
			for i := 0; i < q.Entries; i++ {
				resp = append(resp, wrap(LDAPEntry(id, fmt.Sprintf("CN=obj%d,%s", i, q.Base)), false)...)
			}
			resp = append(resp, wrap(LDAPDone(id), false)...)
			ts = c.Send(ts.Add(2*time.Millisecond), false, resp, 1400)
			id++
		}
	}
	c.Close(ts.Add(5 * time.Millisecond))
	return ts.Add(10 * time.Millisecond)
}

// DCERPCSession writes a raw-TCP DCE/RPC preset to srv:
//   - "wmi-exec": BIND IWbemServices on a dynamic port, ExecMethod;
//   - "epm-drsuapi": ept_map on 135 returns drsuapi's dynamic port, then
//     DRSCrackNames on that port with the BIND before the capture (the
//     interface is learned from the endpoint mapper).
func (b *Builder) DCERPCSession(ts time.Time, cli string, cport func() uint16, srv string, dynPort uint16, preset string) (time.Time, error) {
	send := func(port uint16, steps ...[2]any) {
		c := b.TCP(ts, cli, cport(), srv, port)
		ts = ts.Add(3 * time.Millisecond)
		for _, s := range steps {
			ts = c.Send(ts.Add(2*time.Millisecond), s[0].(bool), s[1].([]byte), 1400)
		}
		c.Close(ts.Add(5 * time.Millisecond))
		ts = ts.Add(10 * time.Millisecond)
	}
	switch preset {
	case "wmi-exec":
		send(dynPort,
			[2]any{true, DCEBind(1, IfaceWbem)}, [2]any{false, DCEBindAck(1, fmt.Sprint(dynPort))},
			[2]any{true, DCERequest(2, 24, make([]byte, 64), 0)}, [2]any{false, DCEResponse(2, make([]byte, 32))})
	case "epm-drsuapi":
		send(135,
			[2]any{true, DCEBind(1, IfaceEPM)}, [2]any{false, DCEBindAck(1, "135")},
			[2]any{true, DCERequest(2, 3, make([]byte, 80), 0)}, [2]any{false, DCEResponse(2, EPTMapResponse(EPMTower(IfaceDRSUAPI, srv, dynPort)))})
		send(dynPort, [2]any{true, DCERequest(10, 12, make([]byte, 40), 5)}, [2]any{true, DCERequest(11, 12, make([]byte, 40), 5)})
	default:
		return ts, fmt.Errorf("dcerpc preset %q: want wmi-exec or epm-drsuapi", preset)
	}
	return ts, nil
}
