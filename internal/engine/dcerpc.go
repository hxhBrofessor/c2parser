package engine

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf16"
)

// DCE/RPC (MS-RPCE) connection-oriented PDUs, over SMB named pipes and raw
// TCP (v10a 2.1). A BIND names the interface by UUID; each REQUEST carries
// an opnum. Mapping both gives Zeek-style endpoint/operation pairs
// ("svcctl" / "CreateServiceW"), which is what lateral movement looks like
// on the wire: PsExec-style service creation, remote scheduled tasks,
// DCSync, PetitPotam coercion, PrintNightmare.
//
// Responses are parsed too: BIND_ACK says which contexts were accepted;
// the endpoint mapper's ept_map response (TCP/135) and DCOM OXID string
// bindings (RemoteCreateInstance, ResolveOxid2) say which dynamic port an
// interface listens on. That map labels a dynamic-port stream whose BIND
// wasn't captured; a visible BIND always wins. Stubs are never inspected
// beyond those two response shapes, and never when the call is sealed.

type rpcIface struct {
	name string
	ops  map[uint16]string
}

func ops(names ...string) map[uint16]string {
	m := map[uint16]string{}
	for i, n := range names {
		if n != "" {
			m[uint16(i)] = n
		}
	}
	return m
}

func opsAt(pairs map[uint16]string) map[uint16]string { return pairs }

// Interface UUIDs (lower-case canonical form) → name and opnum table.
// Opnum names follow the MS-* IDL (MS-SCMR, MS-TSCH, MS-DRSR, MS-EFSR,
// MS-RPRN, MS-SAMR, MS-LSAD/MS-LSAT, MS-NRPC, MS-RPCE EPM, MS-WMI, MS-DCOM).
var rpcIfaces = map[string]rpcIface{
	"367abb81-9844-35f1-ad32-98f038001003": {"svcctl", ops("RCloseServiceHandle", "RControlService", "RDeleteService", "RLockServiceDatabase",
		"RQueryServiceObjectSecurity", "RSetServiceObjectSecurity", "RQueryServiceStatus", "RSetServiceStatus", "RUnlockServiceDatabase",
		"RNotifyBootConfigStatus", "", "RChangeServiceConfigW", "RCreateServiceW", "REnumDependentServicesW", "REnumServicesStatusW",
		"ROpenSCManagerW", "ROpenServiceW", "RQueryServiceConfigW", "RQueryServiceLockStatusW", "RStartServiceW")},
	"1ff70682-0a51-30e8-076d-740be8cee98b": {"atsvc", ops("JobAdd", "JobDel", "JobEnum", "JobGetInfo")},
	"86d35949-83c9-4044-b424-db363231fd0c": {"ITaskSchedulerService", ops("SchRpcHighestVersion", "SchRpcRegisterTask", "SchRpcRetrieveTask",
		"SchRpcCreateFolder", "SchRpcSetSecurity", "SchRpcGetSecurity", "SchRpcEnumFolders", "SchRpcEnumTasks", "SchRpcEnumInstances",
		"SchRpcGetInstanceInfo", "SchRpcStopInstance", "SchRpcStop", "SchRpcRun", "SchRpcDelete", "SchRpcRename",
		"SchRpcScheduledRuntimes", "SchRpcGetLastRunInfo", "SchRpcGetTaskInfo", "SchRpcGetNumberOfMissedRuns", "SchRpcEnableTask")},
	// MS-DRSR §4.1 (opnums 0–12)
	"e3514235-4b06-11d1-ab04-00c04fc2dcd2": {"drsuapi", ops("DRSBind", "DRSUnbind", "DRSReplicaSync", "DRSGetNCChanges", "DRSUpdateRefs",
		"DRSReplicaAdd", "DRSReplicaDel", "DRSReplicaModify", "DRSVerifyNames", "DRSGetMemberships", "DRSInterDomainMove",
		"DRSGetNT4ChangeLog", "DRSCrackNames", "DRSWriteSPN", "DRSRemoveDsServer", "DRSRemoveDsDomain", "DRSDomainControllerInfo",
		"DRSAddEntry", "DRSExecuteKCC", "DRSGetReplInfo")},
	"c681d488-d850-11d0-8c52-00c04fd90f7e": {"efsrpc", ops("EfsRpcOpenFileRaw", "EfsRpcReadFileRaw", "EfsRpcWriteFileRaw", "EfsRpcCloseRaw",
		"EfsRpcEncryptFileSrv", "EfsRpcDecryptFileSrv", "EfsRpcQueryUsersOnFile", "EfsRpcQueryRecoveryAgents",
		"EfsRpcRemoveUsersFromFile", "EfsRpcAddUsersToFile")},
	"df1941c5-fe89-4e79-bf10-463657acf44d": {"efsrpc", ops("EfsRpcOpenFileRaw", "EfsRpcReadFileRaw", "EfsRpcWriteFileRaw", "EfsRpcCloseRaw",
		"EfsRpcEncryptFileSrv", "EfsRpcDecryptFileSrv", "EfsRpcQueryUsersOnFile", "EfsRpcQueryRecoveryAgents",
		"EfsRpcRemoveUsersFromFile", "EfsRpcAddUsersToFile")},
	"12345678-1234-abcd-ef00-0123456789ab": {"spoolss", opsAt(map[uint16]string{0: "RpcEnumPrinters", 1: "RpcOpenPrinter", 14: "RpcAddPrintProcessor", 46: "RpcAddMonitor",
		65: "RpcRemoteFindFirstPrinterChangeNotificationEx", 69: "RpcOpenPrinterEx", 89: "RpcAddPrinterDriverEx"})},
	"12b81e99-f207-4a4c-85d3-77b42f76fd14": {"ISecLogon", ops("SeclCreateProcessWithLogonW", "SeclCreateProcessWithLogonExW")},
	// MS-SAMR §3.1.5 (opnum 4 and 42–43, 59–61, 63 are not used on the wire)
	"12345778-1234-abcd-ef00-0123456789ac": {"samr", ops("SamrConnect", "SamrCloseHandle", "SamrSetSecurityObject", "SamrQuerySecurityObject", "",
		"SamrLookupDomainInSamServer", "SamrEnumerateDomainsInSamServer", "SamrOpenDomain", "SamrQueryInformationDomain",
		"SamrSetInformationDomain", "SamrCreateGroupInDomain", "SamrEnumerateGroupsInDomain", "SamrCreateUserInDomain",
		"SamrEnumerateUsersInDomain", "SamrCreateAliasInDomain", "SamrEnumerateAliasesInDomain", "SamrGetAliasMembership",
		"SamrLookupNamesInDomain", "SamrLookupIdsInDomain", "SamrOpenGroup", "SamrQueryInformationGroup", "SamrSetInformationGroup",
		"SamrAddMemberToGroup", "SamrDeleteGroup", "SamrRemoveMemberFromGroup", "SamrGetMembersInGroup",
		"SamrSetMemberAttributesOfGroup", "SamrOpenAlias", "SamrQueryInformationAlias", "SamrSetInformationAlias", "SamrDeleteAlias",
		"SamrAddMemberToAlias", "SamrRemoveMemberFromAlias", "SamrGetMembersInAlias", "SamrOpenUser", "SamrDeleteUser",
		"SamrQueryInformationUser", "SamrSetInformationUser", "SamrChangePasswordUser", "SamrGetGroupsForUser",
		"SamrQueryDisplayInformation", "SamrGetDisplayEnumerationIndex", "", "", "SamrGetUserDomainPasswordInformation",
		"SamrRemoveMemberFromForeignDomain", "SamrQueryInformationDomain2", "SamrQueryInformationUser2", "SamrQueryDisplayInformation2",
		"SamrGetDisplayEnumerationIndex2", "SamrCreateUser2InDomain", "SamrQueryDisplayInformation3", "SamrAddMultipleMembersToAlias",
		"SamrRemoveMultipleMembersFromAlias", "SamrOemChangePasswordUser2", "SamrUnicodeChangePasswordUser2",
		"SamrGetDomainPasswordInformation", "SamrConnect2", "SamrSetInformationUser2", "", "", "", "SamrConnect4", "", "SamrConnect5",
		"SamrRidToSid", "SamrSetDSRMPassword", "SamrValidatePassword")},
	// MS-LSAD / MS-LSAT (selected opnums)
	"12345778-1234-abcd-ef00-0123456789ab": {"lsarpc", opsAt(map[uint16]string{0: "LsarClose", 2: "LsarEnumeratePrivileges",
		3: "LsarQuerySecurityObject", 6: "LsarOpenPolicy", 7: "LsarQueryInformationPolicy", 11: "LsarEnumerateAccounts",
		13: "LsarEnumerateTrustedDomains", 14: "LsarLookupNames", 15: "LsarLookupSids", 44: "LsarOpenPolicy2", 45: "LsarGetUserName",
		46: "LsarQueryInformationPolicy2", 57: "LsarLookupSids2", 58: "LsarLookupNames2", 68: "LsarLookupNames3",
		76: "LsarLookupSids3", 77: "LsarLookupNames4"})},
	"338cd001-2244-31f1-aaaa-900038001003": {"winreg", nil},
	"4b324fc8-1670-01d3-1278-5a47bf6ee188": {"srvsvc", nil},
	"6bffd098-a112-3610-9833-46c3f87e345a": {"wkssvc", nil},
	// MS-NRPC §3.5.4 (opnums 0–46)
	"12345678-1234-abcd-ef00-01234567cffb": {"netlogon", ops("NetrLogonUasLogon", "NetrLogonUasLogoff", "NetrLogonSamLogon",
		"NetrLogonSamLogoff", "NetrServerReqChallenge", "NetrServerAuthenticate", "NetrServerPasswordSet", "NetrDatabaseDeltas",
		"NetrDatabaseSync", "NetrAccountDeltas", "NetrAccountSync", "NetrGetDCName", "NetrLogonControl", "NetrGetAnyDCName",
		"NetrLogonControl2", "NetrServerAuthenticate2", "NetrDatabaseSync2", "NetrDatabaseRedo", "NetrLogonControl2Ex",
		"NetrEnumerateTrustedDomains", "DsrGetDcName", "NetrLogonGetCapabilities", "NetrLogonSetServiceBits", "NetrLogonGetTrustRid",
		"NetrLogonComputeServerDigest", "NetrLogonComputeClientDigest", "NetrServerAuthenticate3", "DsrGetDcNameEx", "DsrGetSiteName",
		"NetrLogonGetDomainInfo", "NetrServerPasswordSet2", "NetrServerPasswordGet", "NetrLogonSendToSam", "DsrAddressToSiteNamesW",
		"DsrGetDcNameEx2", "NetrLogonGetTimeServiceParentDomain", "NetrEnumerateTrustedDomainsEx", "DsrAddressToSiteNamesExW",
		"DsrGetDcSiteCoverageW", "NetrLogonSamLogonEx", "DsrEnumerateDomainTrusts", "DsrDeregisterDnsHostRecords",
		"NetrServerTrustPasswordsGet", "DsrGetForestTrustInformation", "NetrGetForestTrustInformation",
		"NetrLogonSamLogonWithFlags", "NetrServerGetTrustInfo")},
	// MS-RPCE §2.2.1.2.5 endpoint mapper
	"e1af8308-5d1f-11c9-91a4-08002b14a0fa": {"epmapper", ops("ept_insert", "ept_delete", "ept_lookup", "ept_map",
		"ept_lookup_handle_free", "ept_inq_object", "ept_mgmt_delete")},
	// WMI (DCOM): IWbemServices. opnum 24 = ExecMethod, 25 = ExecMethodAsync
	// (remote command execution, e.g. wmiexec via Win32_Process.Create).
	"9556dc99-828c-11cf-a37e-00aa003240c7": {"IWbemServices", map[uint16]string{6: "OpenNamespace", 20: "PutInstance", 24: "ExecMethod", 25: "ExecMethodAsync"}},
	"027947e1-d731-11ce-a357-000000000001": {"IWbemLevel1Login", ops("EstablishPosition", "RequestChallenge", "WBEMLogin", "NTLMLogin")},
	// DCOM activation (dcomexec / DCOM DLL-hijack). opnum 4 = RemoteCreateInstance.
	"000001a0-0000-0000-c000-000000000046": {"IRemoteSCMActivator", map[uint16]string{3: "RemoteGetClassObject", 4: "RemoteCreateInstance"}},
	"99fcfec4-5260-101b-bbcb-00aa0021347a": {"IObjectExporter", ops("ResolveOxid", "SimplePing", "ComplexPing", "ServerAlive", "ResolveOxid2", "ServerAlive2")},
	// MS-TSTS Standards Assignments (interface names only; opnum names wait
	// for the MS-TSTS IDL appendices)
	"484809d6-4239-471b-b5bc-61df8c23ac48": {"TermSrvSession", nil},
	"11899a43-2b68-4a76-92e3-a3d6ad8c26ce": {"TermSrvNotification", nil},
	"88143fd0-c28d-4b2b-8fef-8d882f6a9390": {"TermSrvEnumeration", nil},
	"bde95fdf-eee0-45de-9e12-e5a61cd0d4fe": {"RCMPublic", nil},
	"497d95a6-2d27-4bf5-9bbd-a6046957133c": {"RCMListener", nil},
	"5ca4a760-ebb1-11cf-8611-00a0245420ed": {"TermSrvLegacy", nil},
}

const (
	uuidEPM       = "e1af8308-5d1f-11c9-91a4-08002b14a0fa"
	uuidDRSUAPI   = "e3514235-4b06-11d1-ab04-00c04fc2dcd2"
	uuidActivator = "000001a0-0000-0000-c000-000000000046"
	uuidExporter  = "99fcfec4-5260-101b-bbcb-00aa0021347a"
)

// rpcRisk scores operations that mean remote execution or credential
// access when called over the network. drsuapi:DRSGetNCChanges is scored
// by the DC guard instead (lateral.go).
var rpcRisk = map[string]struct {
	w    float64
	what string
}{
	"svcctl:RCreateServiceW":                                {0.7, "remote service creation (PsExec / smbexec / Impacket / Havoc jump)"},
	"svcctl:RChangeServiceConfigW":                          {0.6, "remote service reconfiguration (SCShell-style lateral movement)"},
	"svcctl:RStartServiceW":                                 {0.4, "remote service start"},
	"atsvc:JobAdd":                                          {0.7, "remote AT job (atexec)"},
	"ITaskSchedulerService:SchRpcRegisterTask":              {0.7, "remote scheduled task registration (atexec / schtasks /S)"},
	"ITaskSchedulerService:SchRpcRun":                       {0.5, "remote scheduled task run"},
	"efsrpc:EfsRpcOpenFileRaw":                              {0.6, "EFSRPC call (PetitPotam authentication coercion)"},
	"efsrpc:EfsRpcEncryptFileSrv":                           {0.6, "EFSRPC call (PetitPotam authentication coercion)"},
	"spoolss:RpcAddPrinterDriverEx":                         {0.7, "remote printer driver install (PrintNightmare)"},
	"spoolss:RpcRemoteFindFirstPrinterChangeNotificationEx": {0.5, "spooler change notification (PrinterBug coercion)"},
	"ISecLogon:SeclCreateProcessWithLogonW":                 {0.5, "remote process creation with logon"},
	"IWbemServices:ExecMethod":                              {0.7, "remote WMI method call (wmiexec-style execution, e.g. Win32_Process.Create / Win32_ScheduledJob)"},
	"IWbemServices:ExecMethodAsync":                         {0.7, "remote async WMI method call (wmiexec-style execution)"},
	"IRemoteSCMActivator:RemoteCreateInstance":              {0.6, "remote DCOM object activation (dcomexec / DCOM DLL-hijack lateral movement)"},
}

// authLevelName is the MS-RPCE auth level (sec_trailer).
var authLevelName = map[uint8]string{1: "none", 2: "connect", 3: "call", 4: "pkt", 5: "integrity", 6: "privacy"}

// dceLearned is an interface (or DCOM object exporter) learned for a
// dynamic port from an endpoint-mapper or OXID response.
type dceLearned struct {
	uuid string // "" for an OXID binding (the object exporter's port)
	how  string // "ept_map" | "oxid"
}

// dceLearning enables the port map (a var so the mutation test can remove it).
var dceLearning = true

type pendingCall struct {
	iface string
	opnum uint16
}

// dceState is one DCE/RPC association: an SMB pipe open or a TCP connection.
type dceState struct {
	e         *Engine
	transport string         // "smb-pipe" | "tcp"
	server    netip.AddrPort // for the learned-port lookup (tcp)
	fallback  func() string  // endpoint name when the BIND wasn't captured
	emit      func(ep, op string, ts time.Time, frame int64)

	ctx      map[uint16]string // context id → interface uuid
	pendBind []uint16          // context ids of the last BIND / ALTER_CONTEXT, awaiting the ack
	cbuf     []byte            // client → server reassembly
	sbuf     []byte            // server → client reassembly
	reqs     map[uint32]pendingCall
	resp     map[uint32][]byte // call id → response stub so far

	calls   map[string]int      // "iface:op" → count
	unbound map[string]bool     // keys whose BIND wasn't captured
	frames  map[string][2]int64 // key → first, last frame
	auth    map[string]uint8    // key → highest auth level seen
	learned map[string]string   // key → how the interface was learned ("ept_map" | "oxid")
}

func newDCEState(e *Engine, transport string, server netip.AddrPort, fallback func() string, emit func(string, string, time.Time, int64)) *dceState {
	return &dceState{e: e, transport: transport, server: server, fallback: fallback, emit: emit,
		ctx: map[uint16]string{}, reqs: map[uint32]pendingCall{}, resp: map[uint32][]byte{},
		calls: map[string]int{}, unbound: map[string]bool{}, frames: map[string][2]int64{}, auth: map[string]uint8{},
		learned: map[string]string{}}
}

func uuidLE(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint16(b[4:]),
		binary.LittleEndian.Uint16(b[6:]), b[8:10], b[10:16])
}

// looksDCE: a connection-oriented DCE/RPC v5.0 PDU header — version 5.0, a
// PDU type plausible for the direction, NDR data representation (byte 0 of
// drep is 0x00 or 0x10) and a sane fragment length (v10a 2.1: detect by
// header, not by port).
func looksDCE(b []byte, fromClient bool) bool {
	if len(b) < 16 || b[0] != 5 || b[1] != 0 || (b[4] != 0x10 && b[4] != 0x00) {
		return false
	}
	switch t := b[2]; {
	case fromClient && (t == 0 || t == 11 || t == 14 || t == 16):
	case !fromClient && (t == 2 || t == 3 || t == 12 || t == 13 || t == 15):
	default:
		return false
	}
	fl := int(binary.LittleEndian.Uint16(b[8:]))
	if b[4] == 0x00 {
		fl = int(binary.BigEndian.Uint16(b[8:]))
	}
	return fl >= 16 && fl <= 1<<20
}

// feed consumes one direction's bytes.
func (d *dceState) feed(data []byte, fromClient bool, ts time.Time, frame int64) {
	buf := &d.sbuf
	if fromClient {
		buf = &d.cbuf
	}
	*buf = append(*buf, data...)
	for len(*buf) >= 16 {
		b := *buf
		if b[0] != 5 || b[1] != 0 {
			*buf = nil
			return
		}
		le := b[4]&0x10 != 0
		fragLen := int(binary.BigEndian.Uint16(b[8:]))
		if le {
			fragLen = int(binary.LittleEndian.Uint16(b[8:]))
		}
		if fragLen < 16 || fragLen > 1<<20 {
			*buf = nil
			return
		}
		if len(b) < fragLen {
			if len(*buf) > 1<<21 {
				*buf = nil
			}
			return
		}
		pdu := b[:fragLen]
		*buf = b[fragLen:]
		if !le {
			continue // big-endian NDR: header only (Windows is always little-endian)
		}
		d.pdu(pdu, fromClient, ts, frame)
	}
}

// secTrailer returns the auth level and the end of the stub.
func secTrailer(pdu []byte) (level uint8, stubEnd int) {
	authLen := int(binary.LittleEndian.Uint16(pdu[10:]))
	stubEnd = len(pdu)
	if authLen == 0 {
		return 0, stubEnd
	}
	t := len(pdu) - authLen - 8
	if t < 16 {
		return 0, stubEnd
	}
	pad := int(pdu[t+2])
	stubEnd = t - pad
	return pdu[t+1], stubEnd
}

func (d *dceState) pdu(pdu []byte, fromClient bool, ts time.Time, frame int64) {
	flags := pdu[3]
	callID := binary.LittleEndian.Uint32(pdu[12:])
	level, stubEnd := secTrailer(pdu)
	switch pdu[2] {
	case 11, 14: // bind, alter_context
		if !fromClient || len(pdu) < 28 {
			return
		}
		n := int(pdu[24])
		p := 28
		d.pendBind = d.pendBind[:0]
		for i := 0; i < n && p+24 <= len(pdu); i++ {
			id := binary.LittleEndian.Uint16(pdu[p:])
			nts := int(pdu[p+2])
			d.ctx[id] = uuidLE(pdu[p+4 : p+20])
			d.pendBind = append(d.pendBind, id)
			p += 24 + 20*nts
		}
	case 12, 15: // bind_ack, alter_context_resp: drop rejected contexts
		if fromClient || len(pdu) < 28 {
			return
		}
		p := 26 + int(binary.LittleEndian.Uint16(pdu[24:])) // secondary address
		p = (p + 3) &^ 3
		if p+4 > len(pdu) {
			return
		}
		n := int(pdu[p])
		p += 4
		for i := 0; i < n && p+24 <= len(pdu) && i < len(d.pendBind); i++ {
			if res := binary.LittleEndian.Uint16(pdu[p:]); res != 0 { // 0 = acceptance
				delete(d.ctx, d.pendBind[i])
			}
			p += 24
		}
		d.pendBind = d.pendBind[:0]
	case 0: // request
		if !fromClient || len(pdu) < 24 || flags&0x01 == 0 { // first fragment carries the call
			return
		}
		ctxID := binary.LittleEndian.Uint16(pdu[20:])
		opnum := binary.LittleEndian.Uint16(pdu[22:])
		iface, bound := d.ctx[ctxID]
		how := ""
		if !bound && d.transport == "tcp" && dceLearning {
			if l, ok := d.e.dcePorts[d.server]; ok {
				iface, how = l.uuid, l.how
			}
		}
		if len(d.reqs) < 4096 {
			d.reqs[callID] = pendingCall{iface, opnum}
		}
		ep, op := iface, fmt.Sprintf("opnum_%d", opnum)
		if info, ok := rpcIfaces[iface]; ok {
			ep = info.name
			if n, ok := info.ops[opnum]; ok {
				op = n
			}
		}
		switch {
		case ep == "" && how == "oxid":
			ep = "dcom-object" // OXID exporter port; the object's interface is in the unseen BIND
		case ep == "":
			ep = d.fallback()
		}
		key := ep + ":" + op
		if len(d.calls) < 200 || d.calls[key] > 0 {
			d.calls[key]++
			if !bound {
				d.unbound[key] = true
			}
			if how != "" {
				d.learned[key] = how
			}
			if level > d.auth[key] {
				d.auth[key] = level
			}
			fr, ok := d.frames[key]
			if !ok {
				fr[0] = frame
			}
			fr[1] = frame
			d.frames[key] = fr
		}
		if d.emit != nil {
			d.emit(ep, op, ts, frame)
		}
	case 2: // response
		if fromClient || len(pdu) < 24 {
			return
		}
		pc, ok := d.reqs[callID]
		if !ok {
			return
		}
		if level >= 5 { // integrity / privacy: stub is opaque or must not be read
			delete(d.reqs, callID)
			return
		}
		if stubEnd > len(pdu) || stubEnd < 24 {
			stubEnd = len(pdu)
		}
		stub := append(d.resp[callID], pdu[24:stubEnd]...)
		if len(stub) > 1<<20 {
			delete(d.reqs, callID)
			delete(d.resp, callID)
			return
		}
		if flags&0x02 == 0 { // not the last fragment
			d.resp[callID] = stub
			return
		}
		delete(d.resp, callID)
		delete(d.reqs, callID)
		d.response(pc, stub)
	case 3: // fault
		delete(d.reqs, callID)
		delete(d.resp, callID)
	}
}

// response learns dynamic ports from ept_map towers and OXID bindings.
func (d *dceState) response(pc pendingCall, stub []byte) {
	if d.e == nil {
		return
	}
	switch {
	case pc.iface == uuidEPM && pc.opnum == 3:
		for _, t := range eptMapTowers(stub) {
			if t.port == 0 {
				continue
			}
			ip := t.ip
			if !ip.IsValid() || ip.IsUnspecified() {
				ip = d.server.Addr()
			}
			d.e.learnDCEPort(netip.AddrPortFrom(ip, t.port), dceLearned{uuid: t.uuid, how: "ept_map"})
		}
	case (pc.iface == uuidActivator && pc.opnum == 4) || (pc.iface == uuidExporter && (pc.opnum == 0 || pc.opnum == 4)):
		for _, b := range oxidBindings(stub) {
			ip := b.ip
			if !ip.IsValid() {
				ip = d.server.Addr() // hostname binding: same host that answered
			}
			d.e.learnDCEPort(netip.AddrPortFrom(ip, b.port), dceLearned{how: "oxid"})
		}
	}
}

func (e *Engine) learnDCEPort(ap netip.AddrPort, l dceLearned) {
	if e.dcePorts == nil {
		e.dcePorts = map[netip.AddrPort]dceLearned{}
	}
	if old, ok := e.dcePorts[ap]; ok && old.uuid != "" && l.uuid == "" {
		return // an ept_map interface beats a bare OXID binding
	}
	if len(e.dcePorts) < 4096 {
		e.dcePorts[ap] = l
	}
}

// absorb merges another association's call records (SMB per-pipe
// consolidation).
func (d *dceState) absorb(o *dceState) {
	for k, v := range o.calls {
		d.calls[k] += v
	}
	for k, v := range o.unbound {
		d.unbound[k] = d.unbound[k] || v
	}
	for k, fr := range o.frames {
		x, ok := d.frames[k]
		if !ok || fr[0] < x[0] {
			x[0] = fr[0]
		}
		if fr[1] > x[1] {
			x[1] = fr[1]
		}
		d.frames[k] = x
	}
	for k, v := range o.auth {
		if v > d.auth[k] {
			d.auth[k] = v
		}
	}
	for k, v := range o.learned {
		d.learned[k] = v
	}
}

// ------------------------------------------------------------ towers / OXID

type eptTower struct {
	uuid string
	port uint16
	ip   netip.Addr
}

// parseTower decodes one protocol tower (MS-RPCE §2.2.1.2.4 / C706
// appendix L): floor count, then floors of (lhs, rhs) octet strings.
// Floor 1 is the interface (0x0d + UUID + version), TCP is 0x07 with a
// big-endian port, IP is 0x09 with a 4-byte address.
func parseTower(b []byte) (t eptTower, ok bool) {
	if len(b) < 2 {
		return t, false
	}
	n := int(binary.LittleEndian.Uint16(b))
	p := 2
	for i := 0; i < n; i++ {
		if p+2 > len(b) {
			return t, false
		}
		ll := int(binary.LittleEndian.Uint16(b[p:]))
		p += 2
		if ll < 1 || p+ll+2 > len(b) {
			return t, false
		}
		lhs := b[p : p+ll]
		p += ll
		rl := int(binary.LittleEndian.Uint16(b[p:]))
		p += 2
		if p+rl > len(b) {
			return t, false
		}
		rhs := b[p : p+rl]
		p += rl
		switch {
		case i == 0 && lhs[0] == 0x0d && len(lhs) >= 17:
			t.uuid = uuidLE(lhs[1:17])
		case lhs[0] == 0x07 && len(rhs) == 2:
			t.port = binary.BigEndian.Uint16(rhs)
		case lhs[0] == 0x09 && len(rhs) == 4:
			t.ip = netip.AddrFrom4([4]byte(rhs))
		}
	}
	return t, t.uuid != ""
}

// eptMapTowers walks an ept_map response stub (NDR): entry handle (20),
// num_towers (4), the conformant-varying pointer array (max, offset,
// actual, then actual referent ids), then each tower as a conformant
// struct (max_count, tower_length, octets, 4-aligned).
func eptMapTowers(s []byte) []eptTower {
	if len(s) < 40 {
		return nil
	}
	u32 := func(p int) int {
		if p+4 > len(s) {
			return -1
		}
		return int(binary.LittleEndian.Uint32(s[p:]))
	}
	p := 20
	num := u32(p)
	actual := u32(p + 12)
	if num < 0 || actual < 0 || actual > 64 || num > 64 {
		return nil
	}
	p += 16
	refs := 0
	for i := 0; i < actual; i++ {
		if u32(p) != 0 {
			refs++
		}
		p += 4
	}
	var out []eptTower
	for i := 0; i < refs; i++ {
		tl := u32(p + 4)
		if tl < 0 || p+8+tl > len(s) {
			break
		}
		if t, ok := parseTower(s[p+8 : p+8+tl]); ok {
			out = append(out, t)
		}
		p = (p + 8 + tl + 3) &^ 3
	}
	return out
}

type oxidBinding struct {
	ip   netip.Addr
	port uint16
}

// oxidBindings scans a DCOM response stub for ncacn_ip_tcp string bindings
// (DUALSTRINGARRAY entries: tower id 0x0007, then a NUL-terminated UTF-16LE
// "host[port]"). RemoteCreateInstance hides the array inside activation
// properties, so a structural scan is used for both responses.
func oxidBindings(s []byte) []oxidBinding {
	var out []oxidBinding
	for i := 0; i+6 <= len(s) && len(out) < 16; i += 2 {
		if s[i] != 0x07 || s[i+1] != 0 {
			continue
		}
		var u []uint16
		j := i + 2
		for ; j+1 < len(s) && len(u) < 128; j += 2 {
			c := binary.LittleEndian.Uint16(s[j:])
			if c == 0 {
				break
			}
			if c < 0x20 || c > 0x7e {
				u = nil
				break
			}
			u = append(u, c)
		}
		str := string(utf16.Decode(u))
		host, rest, ok := strings.Cut(str, "[")
		if !ok || !strings.HasSuffix(rest, "]") || host == "" {
			continue
		}
		var port int
		if _, err := fmt.Sscanf(strings.TrimSuffix(rest, "]"), "%d", &port); err != nil || port <= 0 || port > 65535 {
			continue
		}
		b := oxidBinding{port: uint16(port)}
		if a, err := netip.ParseAddr(host); err == nil {
			b.ip = a.Unmap()
		}
		out = append(out, b)
		i = j
	}
	return out
}

// Zeek reports operation names without the "R" prefix for svcctl
// (e.g. "CreateServiceW"); Sigma rules are written against Zeek.
func zeekOpName(ep, op string) string {
	if ep == "svcctl" && strings.HasPrefix(op, "R") {
		return op[1:]
	}
	return op
}

// ------------------------------------------------------------ SMB / TCP glue

// feedDCE parses pipe data (WRITE / transceive input from the client,
// READ / transceive output from the server).
func (f *smbFile) feedDCE(data []byte, fromClient bool, ts time.Time, frame int64) {
	if f.dce == nil {
		if !fromClient || len(data) < 16 || data[0] != 5 || data[1] != 0 {
			return // not DCE/RPC v5.0
		}
		c := f.st.c
		f.dce = newDCEState(f.st.e, "smb-pipe", c.server, f.pipeName, func(ep, op string, ts time.Time, frame int64) {
			f.st.e.emitDCERPC(c.client, c.server, ep, op, f.pipeName(), ts, frame)
		})
	}
	f.dce.feed(data, fromClient, ts, frame)
}

// dceConn is a DCE/RPC association on a raw TCP connection.
type dceConn struct {
	c    *tcpConn
	st   *dceState
	last time.Time
}

type dceHalf struct {
	dc     *dceConn
	client bool
}

func (h *dceHalf) gap() {
	if h.client {
		h.dc.st.cbuf = nil
	} else {
		h.dc.st.sbuf = nil
	}
}
func (h *dceHalf) close(time.Time) {}
func (h *dceHalf) feed(data []byte, ts time.Time, frame int64) {
	h.dc.last = ts
	h.dc.st.feed(data, h.client, ts, frame)
}

func (e *Engine) newDCEConn(c *tcpConn) *dceConn {
	dc := &dceConn{c: c, last: c.start}
	dc.st = newDCEState(e, "tcp", c.server, func() string { return "unbound" }, func(ep, op string, ts time.Time, frame int64) {
		e.emitDCERPC(c.client, c.server, ep, op, "", ts, frame)
	})
	e.dceConns = append(e.dceConns, dc)
	return dc
}
