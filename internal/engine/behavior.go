package engine

import (
	"crypto/x509"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"

	"c2parser/internal/stats"
)

// Behavioural signals for when content is hidden: encrypted DNS (DoT, DoH,
// DoQ), long-lived sessions, TLS without SNI, certificates, fingerprints vs
// the host's own baseline, IOC matches, and a per-host cumulative risk.

const CatEncDNS = "Encrypted DNS (DoT/DoH/DoQ)"

// Public DoH/DoT resolvers (hostnames and anycast IPs). Using them from an
// endpoint bypasses enterprise DNS logging. Custom DoH servers (the
// interesting C2 case) won't be here; behaviour catches those.
var dohHosts = map[string]bool{}
var dohIPs = map[netip.Addr]bool{}

func init() {
	for _, h := range strings.Fields(`dns.google dns.google.com cloudflare-dns.com mozilla.cloudflare-dns.com
	one.one.one.one 1dot1dot1dot1.cloudflare-dns.com security.cloudflare-dns.com family.cloudflare-dns.com
	chrome.cloudflare-dns.com dns.quad9.net dns9.quad9.net dns10.quad9.net dns11.quad9.net doh.opendns.com
	doh.familyshield.opendns.com dns.nextdns.io doh.cleanbrowsing.org dns.adguard.com dns.adguard-dns.com
	doh.mullvad.net dns.controld.com freedns.controld.com doh.dns.sb dns.alidns.com doh.pub`) {
		dohHosts[h] = true
	}
	for _, ip := range strings.Fields(`8.8.8.8 8.8.4.4 2001:4860:4860::8888 2001:4860:4860::8844 1.1.1.1 1.0.0.1
	2606:4700:4700::1111 2606:4700:4700::1001 9.9.9.9 149.112.112.112 2620:fe::fe 2620:fe::9
	208.67.222.222 208.67.220.220 94.140.14.14 94.140.15.15`) {
		dohIPs[netip.MustParseAddr(ip)] = true
	}
}

// IOC is one indicator from a user-supplied file.
type IOC struct {
	Kind  string // ip | domain | ja3 | ja3s | ja4 | cert
	Value string
	Label string
}

// ParseIOCLine accepts "kind:value [# label]" or a bare value whose kind is
// inferred (IP, 32-hex → ja3, JA4 shape, 64-hex → cert sha256, else domain).
func ParseIOCLine(line string) (IOC, bool) {
	label := ""
	if i := strings.Index(line, "#"); i >= 0 {
		label = strings.TrimSpace(line[i+1:])
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return IOC{}, false
	}
	kind, val := "", line
	if i := strings.Index(line, ":"); i > 0 {
		switch k := strings.ToLower(line[:i]); k {
		case "ip", "domain", "ja3", "ja3s", "ja4", "cert", "sni", "host":
			kind, val = k, strings.TrimSpace(line[i+1:])
			if kind == "sni" || kind == "host" {
				kind = "domain"
			}
		}
	}
	val = strings.ToLower(strings.TrimSuffix(val, "."))
	if kind == "" {
		switch {
		case func() bool { _, err := netip.ParseAddr(val); return err == nil }():
			kind = "ip"
		case len(val) == 32 && isHexStr(val):
			kind = "ja3"
		case len(val) == 64 && isHexStr(val):
			kind = "cert"
		case len(val) == 36 && strings.Count(val, "_") == 2 && (val[0] == 't' || val[0] == 'q'):
			kind = "ja4"
		default:
			kind = "domain"
		}
	}
	if label == "" {
		label = kind + ":" + val
	}
	return IOC{Kind: kind, Value: val, Label: label}, true
}

func isHexStr(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (e *Engine) ioc(kind, val string) (string, bool) {
	m := e.iocs[kind]
	if m == nil {
		return "", false
	}
	val = strings.ToLower(strings.TrimSuffix(val, "."))
	if l, ok := m[val]; ok {
		return l, true
	}
	if kind == "domain" { // suffix match: evil.com matches a.b.evil.com
		for {
			i := strings.IndexByte(val, '.')
			if i < 0 {
				return "", false
			}
			val = val[i+1:]
			if l, ok := m[val]; ok {
				return l, true
			}
		}
	}
	return "", false
}

func topCount(m map[string]int) (string, int) {
	best, n := "", -1
	for k, v := range m {
		if v > n || v == n && k < best {
			best, n = k, v
		}
	}
	return best, n
}

func firstInvalidSNI(snis map[string]int, cert *x509.Certificate) string {
	for sni := range snis {
		if cert.VerifyHostname(sni) != nil {
			return sni
		}
	}
	return ""
}

func sortedCertHashes(t *tlsAgg) []string {
	keys := make([]string, 0, len(t.certs))
	for h := range t.certs {
		keys = append(keys, h)
	}
	return keys
}

func (e *Engine) scoreBehavior(sc *scorer) {
	start := e.first
	for _, ch := range e.chOrder {
		k := ch.key
		if !e.pairEligible(k.client, k.server) {
			continue
		}
		key := c2Key(k.client, k.server, k.port)
		existing := sc.accs[key]
		var sigs []stats.Signal
		create := false
		names := e.namesOf(k.server)

		// ---- encrypted DNS ----
		var enc []stats.Signal
		alpn := map[string]int{}
		if ch.tls != nil {
			alpn = ch.tls.alpn.Map()
		}
		switch {
		case k.proto == "tcp" && k.port == 853:
			enc = append(enc, stats.Signal{Name: "dot_port", Weight: 0.55, Score: 1, Detail: "TLS to TCP/853 (DNS-over-TLS)"})
		case k.proto == "udp" && (k.port == 853 || k.port == 8853):
			d := "UDP/" + fmt.Sprint(k.port) + " (DNS-over-QUIC port)"
			if ch.quic {
				d = "QUIC on " + d
			}
			enc = append(enc, stats.Signal{Name: "doq_port", Weight: 0.6, Score: 1, Detail: d})
		}
		if alpn["dot"] > 0 || alpn["doq"] > 0 {
			enc = append(enc, stats.Signal{Name: "alpn_encrypted_dns", Weight: 0.7, Score: 1, Detail: "ClientHello ALPN advertises " + fmtCounts(alpn, 3)})
		}
		if k.port == 443 {
			for _, n := range names {
				if dohHosts[n] {
					enc = append(enc, stats.Signal{Name: "doh_public_resolver", Weight: 0.35, Score: 1, Detail: n + " is a public DoH resolver (bypasses enterprise DNS logging)"})
					break
				}
			}
			if dohIPs[k.server] && len(enc) == 0 {
				enc = append(enc, stats.Signal{Name: "doh_public_resolver", Weight: 0.35, Score: 1, Detail: k.server.String() + " is a public DoH/DoT resolver address"})
			}
		}
		if len(enc) > 0 {
			title := fmt.Sprintf("Encrypted DNS %s → %s:%d/%s", k.client, k.server, k.port, k.proto)
			a := sc.get("encdns|"+key[3:], CatEncDNS, title, k.client, k.server, ch.first, ch.last)
			for _, s := range enc {
				a.add(s)
			}
			sigs, _ := e.beacon("encdns", key, channelModel(ch), ch.burstT, ch.burstS, e.cfg.Beacon, 0.5, "client bursts")
			for _, s := range sigs {
				a.add(s)
			}
			if s := ch.bestConnExfil; s > 0 {
				a.add(stats.Signal{Name: "upload_volume_asymmetry", Weight: 0.4, Score: s, Detail: fmt.Sprintf("%s up / %s down", human(ch.out), human(ch.in))})
			}
			if sn := sortedKeysInt(ch.tls); sn != "" {
				a.evidence("SNI: %s", sn)
			}
			a.evidence("%d connections, %s up, %s down, longest %s", ch.conns, human(ch.out), human(ch.in), dur(ch.maxConnSec))
			a.frames(ch.firstFrame)
		}

		// ---- long-lived session (DoH C2 held one connection ~24 h) ----
		if long := stats.Smoothstep(1800, 4*3600, ch.maxConnSec); long > 0 {
			sigs = append(sigs, stats.Signal{Name: "long_connection", Weight: 0.35, Score: long,
				Detail: fmt.Sprintf("single connection held open %s", dur(ch.maxConnSec))})
			create = create || long >= 0.5
		}

		// ---- TLS specifics ----
		if t := ch.tls; t != nil && t.conns > 0 {
			if t.noSNI > 0 {
				frac := float64(t.noSNI) / float64(t.conns)
				sigs = append(sigs, stats.Signal{Name: "tls_no_sni", Weight: 0.3, Score: frac,
					Detail: fmt.Sprintf("%d/%d TLS connections sent no SNI (server addressed by IP)", t.noSNI, t.conns)})
				create = create || frac >= 0.5 && (t.conns >= 3 || ch.maxConnSec >= 600 || ch.out >= 64<<10)
			}
			for _, hash := range sortedCertHashes(t) {
				c := t.certs[hash]
				if why, ok := knownC2Cert(c); ok {
					sigs = append(sigs, stats.Signal{Name: "c2_default_certificate", Weight: 0.95, Score: 1,
						Detail: fmt.Sprintf("%s: subject %q, serial %s", why, c.Subject, c.Serial)})
					create = true
				}
				for _, h := range certAnomalies(c) {
					sigs = append(sigs, stats.Signal{Name: h.name, Weight: h.weight, Score: 1, Detail: h.detail})
					create = create || h.weight >= 0.6
				}
				if c.SelfSigned {
					sigs = append(sigs, stats.Signal{Name: "self_signed_certificate", Weight: 0.35, Score: 1, Detail: "self-signed: " + c.Subject})
					create = true
				}
				if !start.IsZero() && c.NotBefore.After(start.AddDate(0, 0, -14)) && c.NotBefore.Before(e.last) {
					sigs = append(sigs, stats.Signal{Name: "fresh_certificate", Weight: 0.15, Score: 1,
						Detail: fmt.Sprintf("certificate issued %s, <14 days before the traffic", c.NotBefore.Format("2006-01-02"))})
				}
				if !start.IsZero() && c.NotAfter.Before(start) {
					sigs = append(sigs, stats.Signal{Name: "expired_certificate", Weight: 0.15, Score: 1, Detail: "certificate expired " + c.NotAfter.Format("2006-01-02")})
				}
				if c.cert != nil {
					if sni := firstInvalidSNI(t.sni.Map(), c.cert); sni != "" {
						sigs = append(sigs, stats.Signal{Name: "certificate_name_mismatch", Weight: 0.2, Score: 1,
							Detail: fmt.Sprintf("SNI %s not valid for certificate %s", sni, c.Subject)})
					}
				}
			}
			// fingerprint rare for this host (per-device baseline)
			hb := e.baselines[k.client.String()]
			if j4, _ := topCount(t.ja4.Map()); hb != nil && hb.tlsConns >= 10 && j4 != "" {
				servers := 0
				if s := hb.ja4Srv[j4]; s != nil {
					servers = 1
					if s.multi {
						servers = 2
					}
				}
				share := float64(hb.ja4[j4]) / float64(hb.tlsConns)
				if servers == 1 && share < 0.1 {
					sigs = append(sigs, stats.Signal{Name: "rare_tls_fingerprint", Weight: 0.25, Score: 1,
						Detail: fmt.Sprintf("JA4 %s is used by this host only toward this server (%.1f%% of its TLS)", j4, share*100)})
				}
			}
			for kind, m := range map[string]map[string]int{"ja3": t.ja3.Map(), "ja4": t.ja4.Map(), "ja3s": t.ja3s.Map()} {
				for v := range m {
					if l, ok := e.ioc(kind, v); ok {
						sigs = append(sigs, stats.Signal{Name: "ioc:" + kind, Weight: 0.9, Score: 1, Detail: fmt.Sprintf("%s %s matches IOC %q", kind, v, l)})
						create = true
					}
				}
			}
			for _, h := range sortedCertHashes(t) {
				if l, ok := e.ioc("cert", h); ok {
					sigs = append(sigs, stats.Signal{Name: "ioc:cert", Weight: 0.9, Score: 1, Detail: "certificate matches IOC " + l})
					create = true
				}
			}
		}
		if l, ok := e.ioc("ip", k.server.String()); ok {
			sigs = append(sigs, stats.Signal{Name: "ioc:ip", Weight: 0.9, Score: 1, Detail: "server IP matches IOC " + l})
			create = true
		}
		for _, n := range names {
			if l, ok := e.ioc("domain", n); ok {
				sigs = append(sigs, stats.Signal{Name: "ioc:domain", Weight: 0.9, Score: 1, Detail: n + " matches IOC " + l})
				create = true
				break
			}
		}
		// ---- no DNS lookup for this IP (only meaningful if DNS was captured) ----
		if e.counters.DNSResponses >= 20 && !e.resolved[k.server] && len(names) == 0 {
			sigs = append(sigs, stats.Signal{Name: "direct_ip_no_dns", Weight: 0.2, Score: 1,
				Detail: "client never resolved this IP via DNS in the capture and no hostname was used"})
		}

		// Strong signals (encrypted-DNS ports, IOC, C2 certs, long sessions,
		// no-SNI sessions) may open a finding. Baseline rarity, no-DNS and
		// certificate hygiene only amplify a channel with other evidence.
		base := 0.0
		if existing != nil {
			base = existing.score()
		}
		if len(sigs) == 0 || !create && base < 0.15 {
			continue
		}
		a := existing
		if a == nil {
			title := fmt.Sprintf("Suspicious session %s → %s:%d/%s", k.client, k.server, k.port, k.proto)
			a = sc.get(key, CatC2, title, k.client, k.server, ch.first, ch.last)
			a.evidence("%d connections, %s up, %s down, longest %s", ch.conns, human(ch.out), human(ch.in), dur(ch.maxConnSec))
			if t := ch.tls; t != nil {
				j3, _ := topCount(t.ja3.Map())
				j4, _ := topCount(t.ja4.Map())
				a.evidence("TLS: JA3 %s, JA4 %s, SNI %s", j3, j4, orDash(sortedKeysInt(t)))
			}
			a.frames(ch.firstFrame)
		}
		for _, s := range sigs {
			a.add(s)
		}
	}

	// rare User-Agent for this host (HTTP)
	for _, h := range e.httpOrder {
		ua := topKey(h.uas.Map())
		hb := e.baselines[h.key.client.String()]
		a := sc.accs[c2Key(h.key.client, h.key.server, h.key.port)]
		if ua == "" || hb == nil || a == nil || len(hb.ua) < 2 || a.score() < 0.15 {
			continue
		}
		others := 0
		for u, chans := range hb.uaChans {
			if u != ua && chans.count() >= 2 {
				others++
			}
		}
		if hb.uaChans[ua].count() == 1 && others > 0 {
			a.add(stats.Signal{Name: "rare_user_agent", Weight: 0.25, Score: 1,
				Detail: "this User-Agent appears only in this channel; the host's other HTTP traffic uses a different client"})
		}
		if l, ok := e.ioc("domain", h.key.host); ok {
			a.add(stats.Signal{Name: "ioc:domain", Weight: 0.9, Score: 1, Detail: h.key.host + " matches IOC " + l})
		}
	}
}

func sortedCountKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func sortedKeysInt(t *tlsAgg) string {
	if t == nil {
		return ""
	}
	var s []string
	for k := range t.sni.Map() {
		s = append(s, k)
	}
	sort.Strings(s)
	if len(s) > 4 {
		s = append(s[:4], fmt.Sprintf("+%d", len(s)-4))
	}
	return strings.Join(s, ", ")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func dur(sec float64) string {
	switch {
	case sec >= 3600:
		return fmt.Sprintf("%.1fh", sec/3600)
	case sec >= 60:
		return fmt.Sprintf("%.0fm", sec/60)
	}
	return fmt.Sprintf("%.0fs", sec)
}

// HostRisk is the cumulative risk for one internal host: low-fidelity
// signals across protocols add up (noisy-OR over its findings), the way
// Netskope's per-device risk score works, instead of one binary alert.
type HostRisk struct {
	Host       string         `json:"host"`
	Risk       float64        `json:"risk"`
	Severity   string         `json:"severity"`
	Findings   int            `json:"findings"`
	Categories map[string]int `json:"categories"`
	Top        string         `json:"top_finding"`
}

func (e *Engine) hostRisk(fs []Finding) []HostRisk {
	by := map[string]*HostRisk{}
	prod := map[string]float64{}
	for _, f := range fs {
		if f.Client == "" || f.Score < 0.05 {
			continue
		}
		a, err := netip.ParseAddr(f.Client)
		if err != nil || e.scopeOf(a) != scopeInternal && !e.cfg.AllPairs {
			continue
		}
		h := by[f.Client]
		if h == nil {
			h = &HostRisk{Host: f.Client, Categories: map[string]int{}, Top: f.Title}
			by[f.Client] = h
			prod[f.Client] = 1
		}
		h.Findings++
		h.Categories[f.Category]++
		prod[f.Client] *= 1 - f.Score
	}
	var out []HostRisk
	for k, h := range by {
		h.Risk = round2(1 - prod[k])
		h.Severity = stats.Severity(h.Risk)
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Risk > out[j].Risk || out[i].Risk == out[j].Risk && out[i].Host < out[j].Host
	})
	return out
}

var _ = math.Abs
