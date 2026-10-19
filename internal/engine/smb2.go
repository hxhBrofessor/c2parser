package engine

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"c2parser/internal/stats"
)

// SMB2/3 parsing over reassembled TCP/445. Tracks tree connects (share
// names), creates (file / named-pipe names → FileId), and every READ, WRITE
// and pipe-transceive IOCTL so data volume, timing and content can be
// attributed to a specific pipe or file. Both directions of a connection
// share one smbState because responses reference request MessageIds.

const (
	smbCmdSessionSetup = 0x01
	smbCmdTreeConnect  = 0x03
	smbCmdCreate       = 0x05
	smbCmdRead         = 0x08
	smbCmdWrite        = 0x09
	smbCmdIoctl        = 0x0b

	fsctlPipeTransceive = 0x0011C017
	statusOK            = 0x00000000
	statusBufOverflow   = 0x80000005 // pipe read with more data pending
	statusPending       = 0x00000103 // interim async response; the real one follows
	maxPending          = 4096       // cap per map for requests that never get answers
)

type fileID [16]byte

type pendingCreate struct {
	name  string
	tree  uint32
	disp  uint32
	ts    time.Time
	frame int64
}

type smbState struct {
	e            *Engine
	c            *tcpConn
	trees        map[uint32]string
	pendTree     map[uint64]string
	pendCreate   map[uint64]pendingCreate
	pendRead     map[uint64]fileID
	pendIoctl    map[uint64]fileID
	files        map[fileID]*smbFile
	order        []*smbFile
	encMsgs      int
	encBytes     int64
	smb1         bool
	users        map[string]bool
	messages     int
	consolidated bool
}

// smbFile is a file or named pipe opened over one SMB connection.
type smbFile struct {
	st          *smbState
	fid         fileID
	Name        string
	Share       string
	NameKnown   bool
	Created     bool
	OpenFrame   int64
	WriteBytes  int64
	ReadBytes   int64
	Writes      int
	Reads       int
	Transceives int
	opT         []float64
	opS         []float64
	hist        stats.Histogram
	magicHits   int
	mythicHits  int
	magicFrames []int64
	dce         *dceState
	sigs        map[string]int
	first, last time.Time
	firstFrame  int64
	opens       int  // FileIds merged into this record (see consolidate)
	inferred    bool // name attributed after the naming request was lost
}

func (f *smbFile) isPipe() bool {
	if strings.HasSuffix(strings.ToUpper(f.Share), `\IPC$`) {
		return true
	}
	if f.Share == "" {
		// Tree connect predates the capture. Pipe names have no path or
		// extension; C2 framing in the data settles it either way.
		if f.magicHits > 0 || f.mythicHits > 0 {
			return true
		}
		return f.NameKnown && !strings.ContainsAny(f.Name, `.\/`)
	}
	return false
}

// pipeName normalises "\pipe\foo" / "foo" to "foo".
func (f *smbFile) pipeName() string {
	n := strings.ToLower(strings.TrimLeft(f.Name, `\`))
	n = strings.TrimPrefix(n, `pipe\`)
	return n
}

func (f *smbFile) label() string {
	name := f.Name
	if !f.NameKnown {
		name = "<opened before capture> fid=" + hex.EncodeToString(f.fid[:4])
	}
	share := f.Share
	if share == "" {
		share = "<unknown share>"
	}
	if f.inferred {
		name += " (name inferred: naming request lost)"
	}
	return share + `\` + strings.TrimLeft(name, `\`)
}

func newSMBState(e *Engine, c *tcpConn) *smbState {
	s := &smbState{e: e, c: c, trees: map[uint32]string{}, pendTree: map[uint64]string{},
		pendCreate: map[uint64]pendingCreate{}, pendRead: map[uint64]fileID{}, pendIoctl: map[uint64]fileID{},
		files: map[fileID]*smbFile{}, users: map[string]bool{}}
	e.smbStates = append(e.smbStates, s)
	return s
}

func (s *smbState) file(fid fileID, tree uint32, ts time.Time, frame int64) *smbFile {
	f := s.files[fid]
	if f == nil {
		f = &smbFile{st: s, fid: fid, sigs: map[string]int{}, first: ts, firstFrame: frame}
		s.files[fid] = f
		s.order = append(s.order, f)
	}
	if f.Share == "" && tree != 0 {
		f.Share = s.trees[tree]
	}
	return f
}

func (f *smbFile) addData(data []byte, write bool, ts time.Time, frame int64) {
	n := int64(len(data))
	if write {
		f.WriteBytes += n
		f.Writes++
	} else {
		f.ReadBytes += n
		f.Reads++
	}
	if f.first.IsZero() {
		f.first, f.firstFrame = ts, frame
	}
	f.last = ts
	if f.st.e.room(len(f.opT)) {
		f.opT = append(f.opT, f.st.e.rel(ts))
		f.opS = append(f.opS, float64(n))
	}
	f.hist.Add(data)
	f.feedDCE(data, write, ts, frame)
	if h := mythicInText(data); h > 0 {
		f.mythicHits += h
		if len(f.magicFrames) < 10 {
			f.magicFrames = append(f.magicFrames, frame)
		}
	}
	if h := containsC2Magic(data); h > 0 {
		f.magicHits += h
		if len(f.magicFrames) < 10 {
			f.magicFrames = append(f.magicFrames, frame)
		}
	}
	head := data
	if len(head) > headSample {
		head = head[:headSample]
	}
	for _, sg := range matchSignatures(head) {
		f.sigs[sg.Name]++
	}
}

type smbHalf struct {
	st     *smbState
	client bool
	buf    []byte
}

func (h *smbHalf) gap()            { h.buf = h.buf[:0] }
func (h *smbHalf) close(time.Time) {}

func (h *smbHalf) feed(data []byte, ts time.Time, frame int64) {
	h.buf = append(h.buf, data...)
	for len(h.buf) >= 4 {
		if h.buf[0] != 0x00 { // not a NetBIOS session message: resync
			h.resync()
			continue
		}
		l := int(h.buf[1])<<16 | int(h.buf[2])<<8 | int(h.buf[3])
		if l < 4 || l > 16<<20 {
			h.buf = h.buf[1:]
			h.resync()
			continue
		}
		if len(h.buf) < 4+l {
			if len(h.buf) >= 8 && !isSMBMagic(h.buf[4:8]) {
				h.buf = h.buf[1:]
				h.resync()
				continue
			}
			return
		}
		h.st.handle(h.buf[4:4+l], ts, frame)
		h.buf = h.buf[4+l:]
	}
}

func isSMBMagic(b []byte) bool {
	return len(b) >= 4 && (b[0] == 0xfe || b[0] == 0xff || b[0] == 0xfd) && b[1] == 'S' && b[2] == 'M' && b[3] == 'B'
}

func (h *smbHalf) resync() {
	for i := 4; i+4 <= len(h.buf); i++ {
		if isSMBMagic(h.buf[i:]) && h.buf[i-4] == 0 {
			h.buf = h.buf[i-4:]
			return
		}
	}
	if len(h.buf) > 7 {
		h.buf = append(h.buf[:0], h.buf[len(h.buf)-7:]...)
	}
	if len(h.buf) >= 4 && h.buf[0] != 0 {
		h.buf = h.buf[:0]
	}
}

var le = binary.LittleEndian

func (s *smbState) handle(msg []byte, ts time.Time, frame int64) {
	if len(msg) < 4 || msg[1] != 'S' || msg[2] != 'M' || msg[3] != 'B' {
		return
	}
	s.messages++
	s.e.counters.SMBMessages++
	switch msg[0] {
	case 0xfd:
		s.encMsgs++
		s.encBytes += int64(len(msg))
		return
	case 0xff:
		s.smb1 = true
		return
	}
	for off := 0; off+64 <= len(msg); {
		h := msg[off:]
		status := le.Uint32(h[8:])
		cmd := le.Uint16(h[12:])
		flags := le.Uint32(h[16:])
		next := int(le.Uint32(h[20:]))
		mid := le.Uint64(h[24:])
		var tree uint32
		if flags&2 == 0 {
			tree = le.Uint32(h[36:])
		}
		end := len(h)
		if next > 0 && next <= len(h) {
			end = next
		}
		s.command(cmd, flags&1 != 0, status, mid, tree, h[:end], ts, frame)
		if next == 0 || next > len(h) {
			break
		}
		off += next
	}
}

func slice(b []byte, off, n int) []byte {
	if off < 0 || n < 0 || off > len(b) || off+n > len(b) {
		return nil
	}
	return b[off : off+n]
}

func utf16le(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = le.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

func (s *smbState) command(cmd uint16, resp bool, status uint32, mid uint64, tree uint32, pkt []byte, ts time.Time, frame int64) {
	if len(pkt) < 64 {
		return
	}
	if resp && status == statusPending {
		return // keep the pending request: the final async response carries the data
	}
	if !resp {
		s.capPending()
	}
	body := pkt[64:]
	switch cmd {
	case smbCmdSessionSetup:
		if !resp && len(body) >= 16 {
			blob := slice(pkt, int(le.Uint16(body[12:])), int(le.Uint16(body[14:])))
			if d, u, w, ok := parseNTLMAuth(blob); ok && u != "" {
				id := u
				if d != "" {
					id = d + `\` + u
				}
				if w != "" {
					id += " (workstation " + w + ")"
				}
				s.users[id] = true
			}
		}
	case smbCmdTreeConnect:
		if !resp && len(body) >= 8 {
			if p := slice(pkt, int(le.Uint16(body[4:])), int(le.Uint16(body[6:]))); p != nil {
				s.pendTree[mid] = utf16le(p)
			}
		} else if resp {
			if path, ok := s.pendTree[mid]; ok {
				if status == statusOK {
					s.trees[tree] = path
				}
				delete(s.pendTree, mid)
			}
		}
	case smbCmdCreate:
		if !resp && len(body) >= 48 {
			if n := slice(pkt, int(le.Uint16(body[44:])), int(le.Uint16(body[46:]))); n != nil {
				s.pendCreate[mid] = pendingCreate{name: utf16le(n), tree: tree, disp: le.Uint32(body[36:]), ts: ts, frame: frame}
			}
		} else if resp {
			p, ok := s.pendCreate[mid]
			delete(s.pendCreate, mid) // success or failure, the request is done
			if status != statusOK || len(body) < 80 {
				return
			}
			var fid fileID
			copy(fid[:], body[64:80])
			t := tree
			if ok {
				t = p.tree
			}
			f := s.file(fid, t, ts, frame)
			if ok {
				f.Name, f.NameKnown, f.OpenFrame = p.name, true, p.frame
				if f.Share == "" {
					f.Share = s.trees[p.tree]
				}
			}
			f.Created = le.Uint32(body[4:]) == 2 // FILE_CREATED
			s.e.sigmaSMBFile(f, ts, frame)
		}
	case smbCmdRead:
		if !resp && len(body) >= 32 {
			var fid fileID
			copy(fid[:], body[16:32])
			s.pendRead[mid] = fid
		} else if resp {
			// Without the request we can't name the file; data still counts
			// (and is scanned) under the all-zero FileId.
			fid := s.pendRead[mid]
			delete(s.pendRead, mid)
			if (status == statusOK || status == statusBufOverflow) && len(body) >= 8 {
				if data := slice(pkt, int(body[2]), int(le.Uint32(body[4:]))); len(data) > 0 {
					s.file(fid, tree, ts, frame).addData(data, false, ts, frame)
				}
			}
		}
	case smbCmdWrite:
		if !resp && len(body) >= 32 {
			var fid fileID
			copy(fid[:], body[16:32])
			data := slice(pkt, int(le.Uint16(body[2:])), int(le.Uint32(body[4:])))
			if data != nil {
				s.file(fid, tree, ts, frame).addData(data, true, ts, frame)
			}
		}
	case smbCmdIoctl:
		if len(body) < 40 || le.Uint32(body[4:]) != fsctlPipeTransceive {
			return
		}
		var fid fileID
		copy(fid[:], body[8:24])
		if !resp {
			s.pendIoctl[mid] = fid
			if in := slice(pkt, int(le.Uint32(body[24:])), int(le.Uint32(body[28:]))); len(in) > 0 {
				f := s.file(fid, tree, ts, frame)
				f.Transceives++
				f.addData(in, true, ts, frame)
			}
		} else {
			if f0, ok := s.pendIoctl[mid]; ok {
				fid = f0
				delete(s.pendIoctl, mid)
			}
			if status == statusOK || status == statusBufOverflow {
				if out := slice(pkt, int(le.Uint32(body[32:])), int(le.Uint32(body[36:]))); len(out) > 0 {
					s.file(fid, tree, ts, frame).addData(out, false, ts, frame)
				}
			}
		}
	}
}

// capPending drops request bookkeeping that will never be answered (lost
// packets, capture started mid-exchange) so long captures can't grow it.
func (s *smbState) capPending() {
	if len(s.pendTree) > maxPending {
		clear(s.pendTree)
	}
	if len(s.pendCreate) > maxPending {
		clear(s.pendCreate)
	}
	if len(s.pendRead) > maxPending {
		clear(s.pendRead)
	}
	if len(s.pendIoctl) > maxPending {
		clear(s.pendIoctl)
	}
}

// parseNTLMAuth extracts domain/user/workstation from an NTLMSSP
// AUTHENTICATE (type 3) message anywhere inside a security blob.
func parseNTLMAuth(blob []byte) (domain, user, ws string, ok bool) {
	i := bytes.Index(blob, []byte("NTLMSSP\x00"))
	if i < 0 {
		return
	}
	m := blob[i:]
	if len(m) < 52 || le.Uint32(m[8:]) != 3 {
		return
	}
	str := func(o int) string {
		b := slice(m, int(le.Uint32(m[o+4:])), int(le.Uint16(m[o:])))
		if b == nil {
			return ""
		}
		return utf16le(b)
	}
	return str(28), str(36), str(44), true
}

// Named pipes that Windows itself uses. Anything else on IPC$ deserves a look.
var knownPipes = map[string]bool{}

// Pipe names used by default C2 profiles (prefix match).
var c2PipePrefixes = []string{"msagent_", "msse-", "status_", "postex_", "postex_ssh_", "mojo.", "win_svc",
	"ntsvcs_", "scerpc_", "dserNamePipe", "interprocess_", "lsadump", "wkssvc_", "spoolss_", "demoagent_", "gruntsvc",
	"jaccdpqnvbrrxlaf"} // PoshC2 default (resources/config-template.yml)

func init() {
	for _, p := range strings.Fields(`srvsvc wkssvc lsarpc lsass samr netlogon spoolss winreg svcctl atsvc eventlog
	epmapper browser ntsvcs protected_storage scerpc termsrv_api_service lsm_api_service initshutdown
	w32time trkwks efsrpc netdfs dnsserver dhcpserver tapsrv keysvc rpcss ipsec_policyagent
	msfte\mssearch winsock2\catalog_change_listener ctx_winstation_api_service sql\query azuread
	unattended winlogonrpc sessenv audiosrv iisrpc cert router`) {
		knownPipes[p] = true
	}
}

// c2PipePatterns match the default pipe names of public C2 profiles whose
// variable parts are randomised but whose shape is fixed. The Cobalt Strike
// jQuery/Slack/Amazon profiles (e.g. WKL-Sec/Malleable-CS-Profiles) ship the
// stock CS defaults below. Cobalt Strike replaces each '#' with a random hex
// character, so the variable groups are hex, not decimal, and the TSVCPIPE
// suffix is UUID-shaped but not an RFC 4122 v4 UUID (no fixed version nibble).
var c2PipePatterns = []struct {
	re   *regexp.Regexp
	name string
}{
	// CS default beacon pipe: Winsock2\CatalogChangeListener-###-0
	{regexp.MustCompile(`(?i)^winsock2\\catalogchangelistener-[0-9a-f]+-[0-9a-f]+$`), "Cobalt Strike default (CatalogChangeListener)"},
	// CS default stager pipe: TSVCPIPE-########-####-####-####-############
	{regexp.MustCompile(`(?i)^tsvcpipe-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`), "Cobalt Strike default stager (TSVCPIPE)"},
	// CS default SSH pipe: LOCAL\cubeb-pipe-<hex>-<hex>
	{regexp.MustCompile(`(?i)^(local\\)?cubeb-pipe-[0-9a-f]+-[0-9a-f]+$`), "Cobalt Strike default SSH pipe"},
	// CS postex pipe: postex_<4 hex> / postex_ssh_<4 hex>
	{regexp.MustCompile(`(?i)^postex(_ssh)?_[0-9a-f]{4,8}$`), "Cobalt Strike post-ex pipe"},
	// CS SMB beacon default: msagent_<2 hex>
	{regexp.MustCompile(`(?i)^msagent_[0-9a-f]{2,4}$`), "Cobalt Strike SMB beacon (msagent_)"},
}

func classifyPipe(name string) (known bool, c2prefix string) {
	n := strings.ToLower(name)
	for _, pat := range c2PipePatterns {
		if pat.re.MatchString(name) {
			return false, pat.name
		}
	}
	for _, p := range c2PipePrefixes {
		if strings.HasPrefix(n, strings.ToLower(p)) {
			return false, p
		}
	}
	return knownPipes[n], ""
}

func (f *smbFile) String() string {
	return fmt.Sprintf("%s w=%d r=%d", f.label(), f.WriteBytes, f.ReadBytes)
}

// consolidate repairs per-connection pipe bookkeeping after packet loss
// (stress-test finding 7). When the CREATE that names a FileId, or the READ
// request that maps a response to its FileId, is lost, data lands on an
// unnamed FileId or the zero-FileId bucket and used to become its own
// "opened before capture" finding. Rules:
//
//   - an unnamed record on IPC$ (or an unknown share) takes the pipe name
//     when exactly one pipe name is open on this connection;
//   - records with the same pipe name merge (bytes summed, op timings and
//     histograms combined, framing hits kept, opens counted);
//   - the zero-FileId bucket that can't be attributed is kept for the
//     summary but never scored on its own (see scoreSMB).
func (s *smbState) consolidate() {
	if s.consolidated {
		return
	}
	s.consolidated = true
	names := map[string]bool{}
	var share string
	for _, f := range s.order {
		if f.NameKnown && f.isPipe() {
			names[f.pipeName()] = true
			share = f.Share
		}
	}
	if len(names) == 1 {
		var only string
		for n := range names {
			only = n
		}
		for _, f := range s.order {
			if f.NameKnown || (f.Share != "" && !strings.HasSuffix(strings.ToUpper(f.Share), `\IPC$`)) {
				continue
			}
			f.Name, f.NameKnown, f.inferred = only, true, true
			if f.Share == "" {
				f.Share = share
			}
		}
	}
	byName := map[string]*smbFile{}
	var out []*smbFile
	for _, f := range s.order {
		if f.opens == 0 {
			f.opens = 1
		}
		if !(f.NameKnown && f.isPipe()) {
			out = append(out, f)
			continue
		}
		dst := byName[f.pipeName()]
		if dst == nil {
			byName[f.pipeName()] = f
			out = append(out, f)
			continue
		}
		dst.mergeFrom(f)
	}
	s.order = out
}

func (dst *smbFile) mergeFrom(f *smbFile) {
	dst.opens += max(f.opens, 1)
	dst.inferred = dst.inferred && f.inferred
	dst.WriteBytes += f.WriteBytes
	dst.ReadBytes += f.ReadBytes
	dst.Writes += f.Writes
	dst.Reads += f.Reads
	dst.Transceives += f.Transceives
	dst.Created = dst.Created || f.Created
	dst.opT = append(dst.opT, f.opT...)
	dst.opS = append(dst.opS, f.opS...)
	dst.opT, dst.opS = sortOps(dst.opT, dst.opS)
	dst.hist.Merge(&f.hist)
	dst.magicHits += f.magicHits
	dst.mythicHits += f.mythicHits
	for _, fr := range f.magicFrames {
		if len(dst.magicFrames) < 10 {
			dst.magicFrames = append(dst.magicFrames, fr)
		}
	}
	for k, v := range f.sigs {
		dst.sigs[k] += v
	}
	if f.dce != nil {
		if dst.dce == nil {
			dst.dce = f.dce
		} else {
			dst.dce.absorb(f.dce)
		}
	}
	if !f.first.IsZero() && (dst.first.IsZero() || f.first.Before(dst.first)) {
		dst.first, dst.firstFrame = f.first, f.firstFrame
	}
	if f.last.After(dst.last) {
		dst.last = f.last
	}
	if f.OpenFrame > 0 && (dst.OpenFrame == 0 || f.OpenFrame < dst.OpenFrame) {
		dst.OpenFrame = f.OpenFrame
	}
}

// sortOps orders merged operation times (and their sizes) ascending.
func sortOps(t, s []float64) ([]float64, []float64) {
	idx := make([]int, len(t))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return t[idx[a]] < t[idx[b]] })
	ot, os := make([]float64, len(t)), make([]float64, len(s))
	for i, j := range idx {
		ot[i] = t[j]
		if j < len(s) {
			os[i] = s[j]
		}
	}
	return ot, os
}
