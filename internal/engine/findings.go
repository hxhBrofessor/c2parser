package engine

import (
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"c2parser/internal/stats"
)

// Result is everything the engine learned about one capture.
type Result struct {
	File        string               `json:"file"`
	Start       string               `json:"start,omitempty"`
	End         string               `json:"end,omitempty"`
	DurationSec float64              `json:"duration_sec"`
	Counters    Counters             `json:"counters"`
	Hosts       []HostRisk           `json:"host_risk"`
	Findings    []Finding            `json:"findings"`
	HTTP        []HTTPChannelSummary `json:"http_channels"`
	Pipes       []SMBFileSummary     `json:"smb_files"`
	DNS         []DNSDomainSummary   `json:"dns_domains"`
	TopTalkers  []ChannelSummary     `json:"top_talkers"`
	RPCCalls    []RPCCall            `json:"rpc_calls,omitempty"`
	TimingMode  string               `json:"timing_mode,omitempty"`
	Timing      []TimingSeries       `json:"timing_series,omitempty"` // -timing v2
	Conns       []ConnRecord         `json:"conns,omitempty"`         // Config.RecordConns (eval only)
}

// Finding is one scored, explainable detection.
type Finding struct {
	Category    string             `json:"category"`
	Title       string             `json:"title"`
	Score       float64            `json:"score"`
	Severity    string             `json:"severity"`
	Client      string             `json:"client,omitempty"`
	Server      string             `json:"server,omitempty"`
	ServerNames []string           `json:"server_names,omitempty"`
	Signals     []stats.Signal     `json:"signals"`
	Evidence    []string           `json:"evidence,omitempty"`
	Frames      []int64            `json:"frames,omitempty"`
	First       string             `json:"first_seen,omitempty"`
	Last        string             `json:"last_seen,omitempty"`
	Families    map[string]float64 `json:"family_scores,omitempty"` // -timing v2
}

const (
	CatC2      = "C2 channel"
	CatExfil   = "Exfiltration"
	CatPipe    = "SMB named-pipe C2 / pivot"
	CatSMBFile = "SMB file access / staging"
	CatDNS     = "DNS tunnelling / exfil"
	CatDGA     = "DGA / NXDOMAIN spread"
)

type acc struct {
	f    *Finding
	sigs map[string]stats.Signal
	// srv is the server address whose DNS/SNI names fill f.ServerNames,
	// looked up only for findings that are kept or capped (v9c 3.3).
	srv      netip.Addr
	namesSet bool
	reconCap bool // standalone AD recon: capped below high (recon.go)
}

// names fills ServerNames on first need.
func (a *acc) names(e *Engine) {
	if !a.namesSet {
		a.namesSet = true
		if a.srv.IsValid() {
			a.f.ServerNames = e.namesOf(a.srv)
		}
	}
}

func (a *acc) add(s stats.Signal) {
	if s.Score <= 0 || s.Weight <= 0 {
		return
	}
	if old, ok := a.sigs[s.Name]; !ok || s.Contribution() > old.Contribution() {
		a.sigs[s.Name] = s
	}
}

func (a *acc) evidence(format string, args ...any) {
	a.f.Evidence = append(a.f.Evidence, fmt.Sprintf(format, args...))
}

func (a *acc) frames(fr ...int64) {
next:
	for _, f := range fr {
		for _, have := range a.f.Frames {
			if have == f {
				continue next
			}
		}
		if f > 0 && len(a.f.Frames) < 12 {
			a.f.Frames = append(a.f.Frames, f)
		}
	}
}

// capped reports whether the finding would take the fleet / poller /
// scheduler cap at output (timing-only evidence with a benign reason), so
// joins decided before output use the score the analyst will see.
func (a *acc) capped(e *Engine, cad *cadence) bool {
	var s []stats.Signal
	for _, v := range a.sigs {
		s = append(s, v)
	}
	if !onlyTiming(s) {
		return false
	}
	a.names(e)
	return cad.benignReason(a.f) != ""
}

func (a *acc) score() float64 {
	var s []stats.Signal
	for _, v := range a.sigs {
		s = append(s, v)
	}
	return stats.NoisyOR(s)
}

type scorer struct {
	e     *Engine
	accs  map[string]*acc
	order []string
}

// drop removes a finding (merged into another).
func (sc *scorer) drop(key string) {
	if _, ok := sc.accs[key]; !ok {
		return
	}
	delete(sc.accs, key)
	for i, k := range sc.order {
		if k == key {
			sc.order = append(sc.order[:i], sc.order[i+1:]...)
			break
		}
	}
}

func (sc *scorer) get(key, cat, title string, client, server netip.Addr, first, last time.Time) *acc {
	if a, ok := sc.accs[key]; ok {
		return a
	}
	f := &Finding{Category: cat, Title: title}
	if client.IsValid() {
		f.Client = client.String()
	}
	if server.IsValid() {
		f.Server = server.String()
	}
	if !first.IsZero() {
		f.First = first.Format(time.RFC3339)
		f.Last = last.Format(time.RFC3339)
	}
	a := &acc{f: f, sigs: map[string]stats.Signal{}, srv: server}
	sc.accs[key] = a
	sc.order = append(sc.order, key)
	return a
}

func (e *Engine) score() []Finding {
	sc := &scorer{e: e, accs: map[string]*acc{}}
	e.scoreHTTP(sc)
	e.scoreChannels(sc)
	e.scoreTunnels(sc)
	e.scoreSMB(sc)
	e.scoreDNS(sc)
	e.scoreBehavior(sc)
	e.scoreRawStreams(sc)
	e.scoreLateral(sc)
	e.scoreSigma(sc)
	if e.cfg.TimingV2 {
		e.scoreTimingRollups(sc)
	}
	cad := e.cadenceIndex()
	e.correlate(sc, cad)
	e.scoreRecon(sc, cad)

	var out []Finding
	for _, k := range sc.order {
		a := sc.accs[k]
		for _, s := range a.sigs {
			a.f.Signals = append(a.f.Signals, s)
		}
		stats.SortSignals(a.f.Signals)
		for i := range a.f.Signals {
			a.f.Signals[i].Score = round2(a.f.Signals[i].Score)
		}
		if e.cfg.TimingV2 {
			stats.AssignFamilies(a.f.Signals)
			a.f.Families = map[string]float64{}
			for f, v := range stats.ReportedFamilyScores(a.f.Signals) {
				a.f.Families[f] = round2(v)
			}
			a.f.Score = round2(stats.NoisyORFamilies(a.f.Signals))
		} else {
			a.f.Score = round2(stats.NoisyOR(a.f.Signals))
		}
		// v9 Phase 1.3 / rev 2 Phase 0.1 / v9c D2–D3: timing-only findings.
		// A fleet pattern (≥ max(3, 25 % of active internal clients) on one
		// destination), an internal poller (one client → ≥ 3 internal
		// servers) or a scheduler shape caps below medium (fleet.go). A
		// single-host periodic series keeps its score but can't reach
		// critical on timing alone.
		if onlyTiming(a.f.Signals) {
			a.names(e)
			switch why := cad.benignReason(a.f); {
			case why != "" && a.f.Score >= TimingOnlyCap:
				a.f.Score = TimingOnlyCap
				a.f.Evidence = append(a.f.Evidence, "timing-only evidence capped below medium: "+why)
			case why == "" && a.f.Score > TimingOnlyMax:
				a.f.Score = TimingOnlyMax
				a.f.Evidence = append(a.f.Evidence, "timing is the only evidence: capped below critical")
			}
		}
		// v10a.1 D3: AD recon joins a beacon as evidence, but recon on top
		// of timing alone never makes the finding critical.
		if reconCapTiming && a.f.Score > TimingOnlyMax && timingPlusRecon(a.f.Signals) {
			a.f.Score = TimingOnlyMax
			a.f.Evidence = append(a.f.Evidence, "timing and AD recon are the only evidence: capped below critical")
		}
		if a.reconCap && a.f.Score > reconMax {
			a.f.Score = reconMax
			a.f.Evidence = append(a.f.Evidence, "recon from a host with no C2 finding: capped at medium")
		}
		a.f.Severity = stats.Severity(a.f.Score)
		// v9 Phase 1.2: below "low", an HTTP channel is not called C2.
		if a.f.Category == CatC2 && a.f.Score < 0.2 && strings.HasPrefix(a.f.Title, "HTTP C2 ") {
			a.f.Title = "HTTP channel " + strings.TrimPrefix(a.f.Title, "HTTP C2 ")
		}
		if a.f.Score >= 0.05 {
			a.names(e)
			out = append(out, *a.f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

func c2Key(client, server netip.Addr, port uint16) string {
	return fmt.Sprintf("c2|%s|%s|%d", client, server, port)
}

func beaconSignal(b stats.Beacon, weight float64, what string) stats.Signal {
	return stats.Signal{
		Name: "beacon_timing", Weight: weight, Score: stats.Smoothstep(0.55, 0.90, b.Score),
		Detail: fmt.Sprintf("%d %s, median gap %.2fs (mean %.2f ± %.2fs, CV %.2f, p10–p90 %.2f–%.2fs), MAD jitter %.0f%%, %.0f%% of gaps on-period, %.0f%% same size (%s); beacon score %.2f",
			b.Events, what, b.MedianSec, b.MeanSec, b.SDSec, b.CV, b.P10Sec, b.P90Sec, b.JitterPct, b.TSWindow*100, b.DSMode*100, human(int64(b.ModeSize)), b.Score),
	}
}

var anomalyWeights = map[string]float64{
	"ua_c2_default": 0.75, "ua_browser_without_browser_headers": 0.4, "ua_stale_browser": 0.3,
	"ua_legacy_msie": 0.3, "invalid_request_content_type": 0.3, "no_cache_post": 0.15,
	"post_to_ip_literal": 0.2, "ua_missing": 0.2,
}

func (e *Engine) scoreHTTP(sc *scorer) {
	for _, h := range e.httpOrder {
		if h.requests == 0 {
			continue
		}
		k := h.key
		title := fmt.Sprintf("HTTP C2 %s → %s:%d (Host: %s)", k.client, k.server, k.port, k.host)
		a := sc.get(c2Key(k.client, k.server, k.port), CatC2, title, k.client, k.server, h.first, h.last)
		a.frames(h.firstFrame)
		bsigs, _ := e.beacon("http", c2Key(k.client, k.server, k.port)+"|"+k.host, ModelPerRequest, h.reqT, h.reqSize, e.cfg.Beacon, 0.75, "requests")
		for _, s := range bsigs {
			a.add(s)
		}
		for name, n := range h.sigHits {
			a.add(stats.Signal{Name: "sig:" + name, Weight: h.sigWeight[name], Score: 1 - math.Pow(0.5, float64(n)),
				Detail: fmt.Sprintf("%s framing in %d of %d HTTP bodies", name, n, h.requests+h.responses)})
		}
		if n := h.randomUp + h.randomDn; n > 0 {
			ma := h.maxRandom
			a.add(stats.Signal{Name: "random_payloads", Weight: 0.55, Score: 1 - math.Exp(-float64(n)/5),
				Detail: fmt.Sprintf("%d bodies statistically indistinguishable from random (%d up, %d down); strongest: %s, %s, H=%.2f vs %.2f expected (z=%.1f)",
					n, h.randomUp, h.randomDn, human(int64(ma.N)), ma.Alphabet, ma.Entropy, ma.Expected, ma.Z)})
		}
		for name, cnt := range h.anomalies {
			frac := float64(cnt) / float64(h.requests)
			a.add(stats.Signal{Name: "hdr:" + name, Weight: anomalyWeights[name], Score: frac,
				Detail: fmt.Sprintf("%s (%d/%d requests)", h.anomalyDetail[name], cnt, h.requests)})
		}
		if h.legacyHits > 0 {
			a.add(stats.Signal{Name: "legacy_entropy_threshold", Weight: 0.25, Score: 1 - math.Exp(-float64(h.legacyHits)/3),
				Detail: fmt.Sprintf("%d bodies with Shannon ≥ %.2f bits/byte (original tool's metric)", h.legacyHits, e.cfg.LegacyEntropy)})
		}
		e.scoreCarriers(a, h)
		scoreFrameworkDefaults(a, h)
		a.evidence("%d requests / %d responses; %s up, %s down", h.requests, h.responses, human(h.upload), human(h.download))
		if ua := topKey(h.uas.Map()); ua != "" {
			a.evidence("User-Agent: %s", ua)
		}
		if h.methods.len() > 0 {
			a.evidence("methods: %s; URIs: %s", fmtCounts(h.methods.Map(), 4), fmtCounts(h.uris.Map(), 4))
		}
		for _, n := range h.notable {
			if len(a.f.Frames) >= 12 {
				break
			}
			a.frames(n.Frame)
		}
	}
}

// skipBeaconPorts are services that are periodic by design.
var skipBeaconPorts = map[string]bool{"udp/53": true, "udp/123": true, "udp/5353": true, "udp/5355": true,
	"udp/1900": true, "udp/137": true, "udp/138": true, "udp/67": true, "udp/3702": true, "tcp/53": true}

func (e *Engine) pairEligible(client, server netip.Addr) bool {
	cs, ss := e.scopeOf(client), e.scopeOf(server)
	if ss == scopeLocal {
		return false
	}
	if e.cfg.AllPairs {
		return true
	}
	return cs == scopeInternal && ss == scopeExternal
}

func (e *Engine) scoreChannels(sc *scorer) {
	httpByKey := map[string][]*httpChannel{}
	for _, h := range e.httpOrder {
		k := c2Key(h.key.client, h.key.server, h.key.port)
		httpByKey[k] = append(httpByKey[k], h)
	}
	for _, ch := range e.chOrder {
		k := ch.key
		if !e.pairEligible(k.client, k.server) {
			continue
		}
		key := c2Key(k.client, k.server, k.port)
		// --- generic beaconing (TLS, raw TCP, UDP) ---
		wgDNS := wireguardOnDNSPort(ch)
		if !skipBeaconPorts[fmt.Sprintf("%s/%d", k.proto, k.port)] || wgDNS {
			if bsigs, strength := e.beacon("channel", key+"|"+k.proto, channelModel(ch), ch.burstT, ch.burstS, e.cfg.Beacon, 0.65, "client bursts"); strength >= 0.55 || wgDNS {
				title := fmt.Sprintf("Beaconing %s → %s:%d/%s", k.client, k.server, k.port, k.proto)
				if wgDNS {
					title = fmt.Sprintf("WireGuard-shaped tunnel on DNS port %s → %s:%d/udp", k.client, k.server, k.port)
				}
				a := sc.get(key, CatC2, title, k.client, k.server, ch.first, ch.last)
				if strength >= 0.55 {
					for _, s := range bsigs {
						a.add(s)
					}
				}
				if wgDNS {
					a.add(stats.Signal{Name: "wireguard_shape_on_dns_port", Weight: 0.4, Score: 1,
						Detail: fmt.Sprintf("%d of %d client datagrams on UDP 53 are not DNS; %d are 32 B (WireGuard keep-alive size) at a ~25 s cadence", ch.udpNonDNS, ch.pktsOut, ch.udp32Out)})
				}
				a.frames(ch.firstFrame)
				if len(a.f.Evidence) == 0 {
					a.evidence("%d connections, %s up, %s down", ch.conns, human(ch.out), human(ch.in))
				}
			}
		}
		// --- exfiltration ---
		if ch.out < e.cfg.ExfilMinBytes {
			continue
		}
		title := fmt.Sprintf("Upload-heavy transfer %s → %s:%d/%s", k.client, k.server, k.port, k.proto)
		a := sc.get("exfil|"+key[3:], CatExfil, title, k.client, k.server, ch.first, ch.last)
		chanShape := exfilShape(ch.out, ch.in, e.cfg.ExfilHalfBytes)
		a.add(stats.Signal{Name: "upload_volume_asymmetry", Weight: 0.8, Score: math.Max(chanShape, ch.bestConnExfil),
			Detail: fmt.Sprintf("channel %s up / %s down (PCR %.2f)%s", human(ch.out), human(ch.in), pcr(ch.out, ch.in), bestConnDetail(ch))})
		a.frames(ch.bestConnFrame)
		for _, h := range httpByKey[key] {
			if h.randomUpBytes > 0 {
				a.add(stats.Signal{Name: "encrypted_uploads", Weight: 0.5, Score: stats.Saturate(float64(h.randomUpBytes), float64(e.cfg.ExfilHalfBytes)),
					Detail: fmt.Sprintf("%s uploaded in %d request bodies that are indistinguishable from random", human(h.randomUpBytes), h.randomUp)})
			}
			if len(h.fileUploads) > 0 {
				var total int64
				var parts []string
				for i, u := range h.fileUploads {
					total += u.bytes
					if i < 4 {
						parts = append(parts, fmt.Sprintf("%q %s via %s (frame %d)", u.name, human(u.bytes), u.how, u.frame))
					}
					a.frames(u.frame)
				}
				a.add(stats.Signal{Name: "http_file_upload", Weight: 0.65, Score: stats.Saturate(float64(total), 128<<10),
					Detail: fmt.Sprintf("%d file upload(s), %s: %s", len(h.fileUploads), human(total), strings.Join(parts, "; "))})
			}
			if len(h.bigUploadSizes) >= 3 {
				mode, frac := stats.ModeFraction(h.bigUploadSizes, 1)
				n := int(math.Round(frac * float64(len(h.bigUploadSizes))))
				if n >= 3 {
					a.add(stats.Signal{Name: "fixed_size_chunks", Weight: 0.45, Score: frac,
						Detail: fmt.Sprintf("%d of %d large uploads are exactly %s — chunked transfer", n, len(h.bigUploadSizes), human(int64(mode)))})
				}
			}
		}
		a.evidence("%d connections over %s", ch.conns, time.Duration(ch.last.Sub(ch.first).Seconds()*float64(time.Second)).Round(time.Second))
	}
}

func (e *Engine) scoreSMB(sc *scorer) {
	for _, st := range e.smbStates {
		c := st.c
		users := sortedKeys(st.users)
		if e.scopeOf(c.server.Addr()) == scopeExternal {
			title := fmt.Sprintf("SMB to external host %s → %s", c.client.Addr(), c.server.Addr())
			a := sc.get("smbext|"+c.client.Addr().String()+"|"+c.server.Addr().String(), CatSMBFile, title, c.client.Addr(), c.server.Addr(), c.start, c.last)
			a.add(stats.Signal{Name: "smb_external", Weight: 0.7, Score: 1, Detail: "SMB session with a host outside the internal ranges"})
		}
		st.consolidate()
		for _, f := range st.order {
			if f.fid == (fileID{}) && !f.NameKnown {
				continue // unattributable zero-FileId bucket: summary only
			}
			total := f.ReadBytes + f.WriteBytes
			if f.isPipe() {
				pn := f.pipeName()
				known, c2p := classifyPipe(pn)
				title := fmt.Sprintf("Named pipe %s on %s (client %s)", f.label(), c.server.Addr(), c.client.Addr())
				a := sc.get(fmt.Sprintf("pipe|%s|%s|%s", c.client.Addr(), c.server.Addr(), pn), CatPipe, title, c.client.Addr(), c.server.Addr(), f.first, f.last)
				if c2p != "" {
					a.add(stats.Signal{Name: "c2_default_pipe_name", Weight: 0.9, Score: 1, Detail: fmt.Sprintf("pipe name matches C2 default prefix %q", c2p)})
				} else if !known && f.NameKnown {
					a.add(stats.Signal{Name: "unrecognised_pipe", Weight: 0.45, Score: 1, Detail: fmt.Sprintf(`\\pipe\%s is not a standard Windows named pipe`, pn)})
				}
				if uuidPipe.MatchString(pn) {
					a.add(stats.Signal{Name: "uuid_pipe_name", Weight: 0.6, Score: 1,
						Detail: `pipe name is a bare UUID (Mythic smb profile default: random [a-z0-9]{8}-…-{12})`})
				}
				if f.mythicHits > 0 {
					a.add(stats.Signal{Name: "mythic_message_in_pipe", Weight: 0.97, Score: 1 - math.Pow(0.5, float64(f.mythicHits)),
						Detail: fmt.Sprintf("%d Mythic messages (base64 UUID‖ciphertext) in pipe data", f.mythicHits)})
				}
				if f.magicHits > 0 {
					a.add(stats.Signal{Name: "c2_framing_in_pipe", Weight: 0.97, Score: 1 - math.Pow(0.5, float64(f.magicHits)),
						Detail: fmt.Sprintf("Havoc Demon framing (0xDEADBEEF) found %d times in pipe data", f.magicHits)})
					a.frames(f.magicFrames...)
				}
				if total > 0 {
					a.add(stats.Signal{Name: "pipe_volume", Weight: 0.35, Score: stats.Saturate(float64(total), 256<<10),
						Detail: fmt.Sprintf("%s written / %s read through the pipe (%d writes, %d reads, %d transceives)", human(f.WriteBytes), human(f.ReadBytes), f.Writes, f.Reads, f.Transceives)})
				}
				bt, bs, bp := burstify(f.opT, f.opS, e.cfg.BurstGap.Seconds())
				psigs, _ := e.beacon("smb_pipe", fmt.Sprintf("pipe|%s|%s|%s", c.client.Addr(), c.server.Addr(), pn), ModelP2P, bt, bs, bp, 0.5, "pipe I/O bursts")
				for _, s := range psigs {
					a.add(s)
				}
				if as := stats.Assess(&f.hist); as.N >= 1024 && as.Score > 0.5 && known == false {
					a.add(stats.Signal{Name: "random_pipe_data", Weight: 0.3, Score: as.Score,
						Detail: fmt.Sprintf("pipe data is random-looking (%s, H=%.2f vs %.2f expected)", as.Alphabet, as.Entropy, as.Expected)})
				}
				if len(users) > 0 {
					a.evidence("SMB session authenticated as: %s", strings.Join(users, ", "))
				}
				a.frames(f.OpenFrame, f.firstFrame)
				continue
			}
			// regular file on a share
			lower := strings.ToLower(f.Name)
			admin := strings.HasSuffix(strings.ToUpper(f.Share), `\ADMIN$`) || strings.HasSuffix(strings.ToUpper(f.Share), `\C$`)
			execy := false
			for _, ext := range []string{".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".hta", ".sys", ".scr", ".js"} {
				if strings.HasSuffix(lower, ext) {
					execy = true
				}
			}
			if total < e.cfg.ExfilMinBytes/4 && !(execy && f.WriteBytes > 0) {
				continue
			}
			title := fmt.Sprintf("SMB file %s on %s (client %s)", f.label(), c.server.Addr(), c.client.Addr())
			a := sc.get(fmt.Sprintf("file|%s|%s|%s|%x", c.client.Addr(), c.server.Addr(), f.label(), f.fid[:4]), CatSMBFile, title, c.client.Addr(), c.server.Addr(), f.first, f.last)
			if execy && f.WriteBytes > 0 {
				w := 0.5
				if admin {
					w = 0.8
				}
				a.add(stats.Signal{Name: "executable_dropped", Weight: w, Score: 1, Detail: fmt.Sprintf("executable/script written to %s", f.Share)})
			}
			if f.WriteBytes > 0 {
				a.add(stats.Signal{Name: "share_write_volume", Weight: 0.45, Score: stats.Saturate(float64(f.WriteBytes), float64(e.cfg.ExfilHalfBytes)),
					Detail: fmt.Sprintf("%s written (staging / lateral transfer)", human(f.WriteBytes))})
			}
			if f.ReadBytes > 0 {
				a.add(stats.Signal{Name: "share_read_volume", Weight: 0.3, Score: stats.Saturate(float64(f.ReadBytes), float64(e.cfg.ExfilHalfBytes)),
					Detail: fmt.Sprintf("%s read from remote share", human(f.ReadBytes))})
			}
			for name, n := range f.sigs {
				a.add(stats.Signal{Name: "sig:" + name, Weight: 0.4, Score: 1, Detail: fmt.Sprintf("%s content seen %d times", name, n)})
			}
			if len(users) > 0 {
				a.evidence("SMB session authenticated as: %s", strings.Join(users, ", "))
			}
			a.frames(f.OpenFrame, f.firstFrame)
		}
	}
}

// burstify collapses operations closer than gap seconds into one event.
func burstify(t, s []float64, gap float64) ([]float64, []float64, stats.BeaconParams) {
	var bt, bs []float64
	for i := range t {
		if len(bt) > 0 && t[i]-lastOf(bt) <= gap {
			bs[len(bs)-1] += s[i]
			continue
		}
		bt = append(bt, t[i])
		bs = append(bs, s[i])
	}
	return bt, bs, stats.DefaultBeaconParams
}

func lastOf(x []float64) float64 { return x[len(x)-1] }

type dnsFeat struct {
	u        int
	avgLen   float64
	agg      stats.Assessment // all subdomain characters
	pos      positional       // column-wise, framing stripped
	r        float64          // best randomness estimate (aggregate or framing-stripped)
	encoded  float64
	ratio    float64 // unique names / logical queries
	rawRatio float64 // unique names / raw queries (Luise's original)
}

func (e *Engine) dnsFeatures(d *dnsDomain) dnsFeat {
	sh := d.subHistogram()
	f := dnsFeat{u: len(d.subs), agg: stats.Assess(&sh), pos: positionalProfile(d.labels)}
	if f.u > 0 {
		f.avgLen = float64(d.subChars) / float64(f.u)
	}
	f.r = math.Max(f.agg.Score, math.Max(f.pos.Remainder.Score, f.pos.Score))
	k := f.agg.Alphabet.Size()
	if f.pos.Remainder.N > 0 && f.pos.Remainder.Score > f.agg.Score {
		k = f.pos.Remainder.Alphabet.Size()
	}
	f.encoded = float64(d.subChars) * math.Log2(float64(k)) / 8
	if d.logical > 0 {
		f.ratio = float64(f.u) / float64(d.logical)
	}
	if d.queries > 0 {
		f.rawRatio = float64(f.u) / float64(d.queries)
	}
	return f
}

func (e *Engine) scoreDNS(sc *scorer) {
	e.contacted = map[netip.Addr]bool{}
	for _, ch := range e.chOrder {
		if ch.out > 0 && ch.key.port != 53 {
			e.contacted[ch.key.server] = true
		}
	}
	for _, d := range e.dns.domains {
		ft := e.dnsFeatures(d)
		u, avgLen, as, encoded := ft.u, ft.avgLen, ft.agg, ft.encoded
		// best beacon among this domain's clients
		var best stats.Beacon
		var bestClient netip.Addr
		var bestSigs []stats.Signal
		bestStrength := 0.0
		top, topN := netip.Addr{}, 0
		for c, s := range d.clients {
			if len(s.t) > topN {
				top, topN = c, len(s.t)
			}
			if e.cfg.TimingV2 {
				if sigs, st := e.beacon("dns", "dns|"+d.base+"|"+c.String(), ModelPerRequest, s.t, s.size, e.cfg.Beacon, 0.5, "queries"); st > bestStrength {
					bestSigs, bestStrength, bestClient = sigs, st, c
				}
			} else if b, ok := stats.ScoreBeacon(s.t, s.size, e.cfg.Beacon); ok && b.Score > best.Score {
				best, bestClient = b, c
			}
		}
		csSig, csHit := csDNSSignal(d)
		if u < 5 && math.Max(best.Score, bestStrength) < 0.55 && !csHit {
			if _, hit := e.ioc("domain", d.base); !hit {
				continue
			}
		}
		if bestClient.IsValid() {
			top = bestClient
		}
		title := fmt.Sprintf("DNS tunnel candidate *.%s (client %s)", d.base, top)
		a := sc.get("dns|"+d.base, CatDNS, title, top, netip.Addr{}, d.first, d.last)
		a.f.Server = d.base
		r := ft.r
		// Randomness only modulates this signal (floor 0.4): Sliver's DNS C2
		// keeps per-name entropy in the normal range on purpose.
		a.add(stats.Signal{Name: "unique_subdomains", Weight: 0.55, Score: (1 - math.Exp(-float64(u)/150)) * math.Max(0.4, r),
			Detail: fmt.Sprintf("%d unique subdomains in %d queries; charset %s, randomness %.2f (whole-name H=%.2f vs %.2f expected; framing-stripped %.2f)", u, d.queries, as.Alphabet, r, as.Entropy, as.Expected, ft.pos.Remainder.Score)})
		// Column-wise randomness with constant framing removed.
		if ft.pos.Varying > 0 {
			a.add(stats.Signal{Name: "positional_randomness", Weight: 0.45, Score: ft.pos.Score * stats.Clamp01(float64(u-10)/40),
				Detail: fmt.Sprintf("%d varying label positions are %.0f%% as random as %s allows; %d constant positions", ft.pos.Varying, ft.pos.Ratio*100, ft.pos.Remainder.Alphabet, ft.pos.Constant)})
		}
		if len(ft.pos.Prefix) >= 2 && ft.pos.Score > 0 {
			a.add(stats.Signal{Name: "framing_prefix", Weight: 0.3, Score: ft.pos.Score,
				Detail: fmt.Sprintf("%q prefixes ≥90%% of names, followed by random data: an encoder header, not a hostname", ft.pos.Prefix)})
		}
		if d.answerRRs >= 10 && u >= 10 {
			if f := float64(d.ttl0) / float64(d.answerRRs); f > 0.5 {
				a.add(stats.Signal{Name: "ttl_zero_answers", Weight: 0.2, Score: f * stats.Clamp01(float64(u)/20),
					Detail: fmt.Sprintf("%d/%d answers have TTL 0 (uncacheable: every query must reach the authoritative server)", d.ttl0, d.answerRRs)})
			}
		}
		if d.responses > 0 && d.dataResps > 0 && u >= 10 {
			a.add(stats.Signal{Name: "data_in_address_answers", Weight: 0.3, Score: float64(d.dataResps) / float64(d.responses) * stats.Clamp01(float64(u)/20),
				Detail: fmt.Sprintf("%d/%d responses carry ≥4 A/AAAA records (address records used as a data channel)", d.dataResps, d.responses)})
		}
		// Luise (2024): cardinality/volume of names per domain. Tunnels and
		// DNS beacons generate a fresh name almost every query; legitimate
		// domains repeat a few names. Entropy-independent. Ratio > 0.5 (0.4
		// on noisy production data) with volume ≥ 20.
		// Computed on *logical* queries: repeats of the same name by the same
		// client within 3 s (retries, A/AAAA/TXT twins) count once.
		if d.logical >= 20 {
			a.add(stats.Signal{Name: "name_cardinality_ratio", Weight: 0.5, Score: stats.Smoothstep(0.4, 0.8, ft.ratio) * stats.Clamp01(float64(d.logical-10)/40),
				Detail: fmt.Sprintf("%d distinct names / %d logical queries = %.2f (raw %d queries incl. %d retries/twins → %.2f); tunnels ≈1, normal domains ≪ 0.4",
					u, d.logical, ft.ratio, d.queries, d.retries, ft.rawRatio)})
		}
		// Resolution without follow-up: answers that the client never connects to.
		if len(d.answers) >= 5 && u >= 10 {
			never := 0
			for ip := range d.answers {
				if !e.contacted[ip] {
					never++
				}
			}
			frac := float64(never) / float64(len(d.answers))
			a.add(stats.Signal{Name: "resolved_never_contacted", Weight: 0.3, Score: frac * stats.Clamp01(float64(u-10)/40),
				Detail: fmt.Sprintf("%d of %d answer IPs were never connected to (answers carry data, not destinations)", never, len(d.answers))})
		}
		if csHit {
			a.add(csSig)
		}
		if l, ok := e.ioc("domain", d.base); ok {
			a.add(stats.Signal{Name: "ioc:domain", Weight: 0.9, Score: 1, Detail: d.base + " matches IOC " + l})
		}
		a.add(stats.Signal{Name: "long_names", Weight: 0.4, Score: stats.Clamp01((avgLen-20)/40) * math.Max(0.3, r),
			Detail: fmt.Sprintf("mean subdomain length %.1f chars", avgLen)})
		a.add(stats.Signal{Name: "long_labels", Weight: 0.3, Score: stats.Clamp01(float64(d.maxLabel-30) / 30),
			Detail: fmt.Sprintf("longest label %d chars (max 63)", d.maxLabel)})
		tun := float64(d.qtypes["TXT"]+d.qtypes["NULL"]) + 0.5*float64(d.qtypes["CNAME"]+d.qtypes["MX"])
		if d.queries > 0 && tun > 0 {
			a.add(stats.Signal{Name: "tunnel_record_types", Weight: 0.35, Score: tun / float64(d.queries) * stats.Clamp01(float64(u)/20),
				Detail: fmt.Sprintf("record types: %s; %s of TXT/NULL answer data", fmtCounts(d.qtypes, 5), human(d.txtBytes))})
		}
		a.add(stats.Signal{Name: "encoded_volume", Weight: 0.6, Score: stats.Saturate(encoded, 16<<10) * r,
			Detail: fmt.Sprintf("≈%s of data encoded in query names (%d chars × %.1f bits)", human(int64(encoded)), d.subChars, math.Log2(float64(as.Alphabet.Size())))})
		for _, bs := range bestSigs {
			// same name-cardinality scaling as v1 (cache refresh vs. C2)
			bs.Score *= math.Max(0.3, math.Min(1, ft.ratio))
			a.add(bs)
		}
		if best.Score > 0 {
			// Re-resolving the same few names on a timer is cache refresh;
			// a beacon that changes the name every time is C2. Scale the
			// timing evidence by name cardinality (floor 0.3).
			bs := beaconSignal(best, 0.5, "queries")
			bs.Score *= math.Max(0.3, math.Min(1, ft.ratio))
			bs.Detail += fmt.Sprintf(" (×%.2f for name cardinality)", math.Max(0.3, math.Min(1, ft.ratio)))
			a.add(bs)
		}
		if len(d.samples) > 0 {
			a.evidence("longest names: %s", strings.Join(d.samples[:min(3, len(d.samples))], ", "))
		}
		a.frames(d.firstFrame)
	}
	for client, c := range e.dns.clients {
		n := len(c.nxBases)
		if n < 5 {
			continue
		}
		as := stats.Assess(&c.nxHist)
		title := fmt.Sprintf("NXDOMAIN spread from %s (%d distinct failing domains)", client, n)
		a := sc.get("dga|"+client.String(), CatDGA, title, client, netip.Addr{}, time.Time{}, time.Time{})
		a.add(stats.Signal{Name: "nxdomain_spread", Weight: 0.75, Score: (1 - math.Exp(-float64(n)/20)) * math.Max(0.25, as.Score),
			Detail: fmt.Sprintf("%d registrable domains returned NXDOMAIN; label randomness %.2f (%s)", n, as.Score, as.Alphabet)})
		var names []string
		for b := range c.nxBases {
			names = append(names, b)
		}
		sort.Strings(names)
		a.evidence("examples: %s", strings.Join(names[:min(5, len(names))], ", "))
	}
}

// correlateCapAware skips capped C2 findings in correlate (mutation hook).
var correlateCapAware = true

// correlate links findings across protocols: a host that already runs an
// HTTP C2 channel and then opens a non-standard pipe on a peer is the
// textbook Havoc/Cobalt Strike SMB pivot.
//
// A C2 finding that would take the fleet / poller / scheduler cap at
// output (0.39) lends nothing: the decision uses the capped score the
// analyst sees (v10b; same rule as the recon join).
func (e *Engine) correlate(sc *scorer, cad *cadence) {
	usable := func(a *acc) bool { return !correlateCapAware || !a.capped(e, cad) }
	c2Hosts := map[string]string{}
	for _, k := range sc.order {
		a := sc.accs[k]
		if a.f.Category == CatC2 && a.score() >= 0.65 && usable(a) {
			c2Hosts[a.f.Client] = a.f.Server
		}
	}
	for _, k := range sc.order {
		a := sc.accs[k]
		switch a.f.Category {
		case CatPipe:
			if srv, ok := c2Hosts[a.f.Client]; ok && a.score() > 0.3 {
				a.add(stats.Signal{Name: "pivot_from_c2_host", Weight: 0.5, Score: 1,
					Detail: fmt.Sprintf("client %s also has an active C2 channel to %s", a.f.Client, srv)})
			}
		case CatExfil:
			// An amplifier, not standalone evidence: it scales with the
			// strongest exfil signal already present, so a C2 channel with
			// ordinary traffic volume isn't reported as exfiltration.
			if c2 := sc.accs[c2Key(mustAddr(a.f.Client), mustAddr(a.f.Server), portOf(k))]; c2 != nil && c2.score() >= 0.65 && usable(c2) {
				best := 0.0
				for _, s := range a.sigs {
					best = math.Max(best, s.Score)
				}
				a.add(stats.Signal{Name: "same_channel_as_c2", Weight: 0.6, Score: c2.score() * best,
					Detail: "uploads ride the same client/server/port as a detected C2 channel"})
			}
		}
	}
}

var uuidPipe = regexp.MustCompile(`^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$`)

func mustAddr(s string) netip.Addr { a, _ := netip.ParseAddr(s); return a }

func portOf(key string) uint16 {
	parts := strings.Split(key, "|")
	var p uint16
	fmt.Sscanf(parts[len(parts)-1], "%d", &p)
	return p
}

// ---------------------------------------------------------------- helpers

func human(n int64) string {
	f := float64(n)
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", f/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2f MB", f/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", f/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func topKey(m map[string]int) string {
	best, bn := "", -1
	for k, v := range m {
		if v > bn || v == bn && k < best {
			best, bn = k, v
		}
	}
	return best
}

func fmtCounts(m map[string]int, n int) string {
	type kv struct {
		k string
		v int
	}
	var s []kv
	for k, v := range m {
		s = append(s, kv{k, v})
	}
	sort.Slice(s, func(i, j int) bool { return s[i].v > s[j].v || s[i].v == s[j].v && s[i].k < s[j].k })
	var parts []string
	for i, x := range s {
		if i == n {
			parts = append(parts, fmt.Sprintf("+%d more", len(s)-n))
			break
		}
		parts = append(parts, fmt.Sprintf("%s×%d", x.k, x.v))
	}
	return strings.Join(parts, ", ")
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func bestConnDetail(ch *channel) string {
	if ch.bestConnOut == 0 {
		return ""
	}
	return fmt.Sprintf("; busiest single connection %s up / %s down (PCR %.2f)", human(ch.bestConnOut), human(ch.bestConnIn), pcr(ch.bestConnOut, ch.bestConnIn))
}

// scoreCarriers turns per-location token statistics, WebSocket messages and
// response-header defaults into signals on the channel's C2 finding.
func (e *Engine) scoreCarriers(a *acc, h *httpChannel) {
	locs := make([]string, 0, len(h.carriers))
	for l := range h.carriers {
		locs = append(locs, l)
	}
	sort.Strings(locs)
	for _, loc := range locs {
		cs := h.carriers[loc]
		if cs.mythic > 0 {
			a.add(stats.Signal{Name: "sig:mythic-agent-message", Weight: 0.97, Score: 1 - math.Pow(0.5, float64(cs.mythic)),
				Detail: fmt.Sprintf("Mythic message (base64 UUID‖ciphertext) in %s of %d requests", loc, cs.mythic)})
		}
		if cs.requests < 5 || cs.random == 0 {
			continue
		}
		kind, _, _ := strings.Cut(loc, ":")
		frac := float64(cs.random) / float64(cs.requests)
		a.add(stats.Signal{Name: "encoded_payload_in_" + kind, Weight: 0.55, Score: frac * stats.Clamp01(float64(cs.requests-3)/10),
			Detail: fmt.Sprintf("%s: %d/%d requests carry a fresh, random-after-decoding token (%s), e.g. %s",
				loc, cs.random, cs.requests, fmtCounts(cs.encs, 3), cs.example)})
	}
	for name, n := range h.respAnoms {
		if h.responses > 0 {
			a.add(stats.Signal{Name: "hdr:" + name, Weight: 0.5, Score: float64(n) / float64(h.responses),
				Detail: fmt.Sprintf("%s (%d/%d responses)", h.respAnomDetail[name], n, h.responses)})
		}
	}
	if w := h.ws; w != nil {
		a.evidence("WebSocket: %d client / %d server messages, %s up, %s down", w.clientMsgs, w.serverMsgs, human(w.bytesUp), human(w.bytesDown))
		model := ModelPerRequest
		if w.push {
			// v9c 2.2: in push mode the server sends when it has something;
			// client timing is not a check-in schedule. Refuse it.
			model = ModelPush
			a.add(stats.Signal{Name: "websocket_push_mode", Weight: 0.1, Score: 1,
				Detail: "WebSocket upgrade requested server-push mode (Accept-Type: Push); timing is not scored"})
		}
		wsigs, _ := e.beacon("websocket", c2Key(h.key.client, h.key.server, h.key.port)+"|ws", model, w.clientT, w.clientS, e.cfg.Beacon, 0.7, "WebSocket client messages")
		for _, s := range wsigs {
			a.add(s)
		}
		if w.mythic > 0 {
			a.add(stats.Signal{Name: "sig:mythic-agent-message", Weight: 0.97, Score: 1 - math.Pow(0.5, float64(w.mythic)),
				Detail: fmt.Sprintf("Mythic message in %d WebSocket messages", w.mythic)})
		}
		if w.havoc > 0 {
			a.add(stats.Signal{Name: "sig:havoc-demon-header", Weight: 0.97, Score: 1 - math.Pow(0.5, float64(w.havoc)),
				Detail: fmt.Sprintf("Havoc framing in %d WebSocket messages", w.havoc)})
		}
		if w.random > 0 {
			a.add(stats.Signal{Name: "random_ws_payloads", Weight: 0.5, Score: 1 - math.Exp(-float64(w.random)/5),
				Detail: fmt.Sprintf("%d WebSocket messages are random after decoding", w.random)})
		}
		a.frames(w.frames...)
	}
}

// scoreRawStreams flags C2 framing found in unclassified TCP streams.
// Peer-to-peer links (Mythic tcp, Havoc/Sliver pivots) are usually
// internal↔internal, so scope rules don't apply here.
func (e *Engine) scoreRawStreams(sc *scorer) {
	for _, ch := range e.chOrder {
		r := ch.raw
		if r == nil || r.havoc+r.mythic == 0 {
			continue
		}
		k := ch.key
		title := fmt.Sprintf("C2 framing in raw TCP %s → %s:%d", k.client, k.server, k.port)
		if e.scopeOf(k.client) == scopeInternal && e.scopeOf(k.server) == scopeInternal {
			title = fmt.Sprintf("Peer-to-peer C2 link (TCP) %s → %s:%d", k.client, k.server, k.port)
		}
		a := sc.get(c2Key(k.client, k.server, k.port), CatC2, title, k.client, k.server, ch.first, ch.last)
		if r.mythic > 0 {
			a.add(stats.Signal{Name: "sig:mythic-agent-message", Weight: 0.97, Score: 1 - math.Pow(0.5, float64(r.mythic)),
				Detail: fmt.Sprintf("%d Mythic messages in the TCP stream", r.mythic)})
		}
		if r.havoc > 0 {
			a.add(stats.Signal{Name: "sig:havoc-demon-header", Weight: 0.97, Score: 1 - math.Pow(0.5, float64(r.havoc)),
				Detail: fmt.Sprintf("%d Havoc frames in the TCP stream", r.havoc)})
		}
		a.evidence("%d connections, %s up, %s down", ch.conns, human(ch.out), human(ch.in))
		a.frames(r.frames...)
	}
}

// TimingOnlyCap is the maximum score of a timing-only finding that looks
// like a fleet scheduler; TimingOnlyMax bounds every other timing-only
// finding below critical.
const (
	TimingOnlyCap = 0.39
	TimingOnlyMax = 0.84
	// negligible is the contribution (score × weight) below which a
	// non-timing signal doesn't count as evidence for the cap.
	negligible = 0.05
)

// reconCapTiming enables the D3 cap (mutation hook).
var reconCapTiming = true

// timingPlusRecon: the finding's evidence is timing (with session shape)
// plus recon_from_c2_host and nothing else.
func timingPlusRecon(sigs []stats.Signal) bool {
	recon := false
	var rest []stats.Signal
	for _, sg := range sigs {
		if sg.Name == "recon_from_c2_host" {
			recon = recon || sg.Contribution() >= negligible
			continue
		}
		rest = append(rest, sg)
	}
	return recon && onlyTiming(rest)
}

func onlyTiming(sigs []stats.Signal) bool {
	timing := false
	for _, sg := range sigs {
		if f := stats.FamilyOf(sg.Name); f == "timing" {
			timing = true
		}
	}
	if !timing {
		return false
	}
	for _, sg := range sigs {
		if sg.Contribution() < negligible {
			continue
		}
		// long_connection is session shape (duration), not evidence of
		// what the traffic is; it rides with timing for this cap.
		if f := stats.FamilyOf(sg.Name); f != "timing" && f != "long_connection" {
			return false
		}
	}
	return true
}
