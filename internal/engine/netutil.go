package engine

import (
	"fmt"
	"net/netip"
	"strings"
)

// DefaultInternal is RFC1918 + loopback + link-local + ULA. CGNAT
// (100.64.0.0/10, used by Tailscale) is deliberately *not* included: add it
// with -internal if your environment uses it internally.
var DefaultInternal = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
	"169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128",
}

// ParsePrefixes parses a comma-separated CIDR list.
func ParsePrefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, err2 := netip.ParseAddr(s)
			if err2 != nil {
				return nil, fmt.Errorf("bad CIDR %q: %w", s, err)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// scope classifies an address relative to the monitored network.
type scope int

const (
	scopeExternal scope = iota
	scopeInternal
	scopeLocal // multicast / broadcast / unspecified: never an exfil target
)

func (e *Engine) scopeOf(a netip.Addr) scope {
	a = a.Unmap()
	if a.IsMulticast() || a.IsUnspecified() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return scopeLocal
	}
	if a.Is4() && a.As4()[3] == 255 && e.isInternal(a) {
		return scopeLocal // likely subnet broadcast
	}
	if e.isInternal(a) {
		return scopeInternal
	}
	return scopeExternal
}

func (e *Engine) isInternal(a netip.Addr) bool {
	for _, p := range e.internal {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// wellKnownServerPorts helps orient flows whose handshake was not captured.
var wellKnownServerPorts = map[uint16]bool{
	20: true, 21: true, 22: true, 23: true, 25: true, 53: true, 67: true, 69: true, 80: true, 88: true,
	110: true, 123: true, 135: true, 137: true, 138: true, 139: true, 143: true, 161: true, 389: true,
	443: true, 445: true, 464: true, 465: true, 514: true, 587: true, 636: true, 993: true, 995: true,
	1433: true, 1900: true, 3268: true, 3269: true, 3306: true, 3389: true, 5353: true, 5355: true,
	5432: true, 5985: true, 5986: true, 8080: true, 8443: true, 8000: true, 8888: true, 9090: true,
}

// guessServerIsDst decides orientation from ports alone.
func guessServerIsDst(sport, dport uint16) bool {
	sw, dw := wellKnownServerPorts[sport], wellKnownServerPorts[dport]
	switch {
	case dw && !sw:
		return true
	case sw && !dw:
		return false
	}
	return dport < sport
}

// baseDomain approximates the registrable domain (eTLD+1) without network
// access to the public-suffix list: last two labels, or three when the
// last two form a common multi-label public suffix.
func baseDomain(name string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	labels := strings.Split(name, ".")
	if len(labels) <= 2 {
		return name
	}
	last2 := labels[len(labels)-2] + "." + labels[len(labels)-1]
	if multiSuffix[last2] && len(labels) >= 3 {
		return strings.Join(labels[len(labels)-3:], ".")
	}
	return last2
}

var multiSuffix = map[string]bool{}

func init() {
	for _, s := range strings.Fields(`co.uk org.uk ac.uk gov.uk ltd.uk plc.uk me.uk net.uk
	com.au net.au org.au edu.au gov.au co.nz org.nz co.jp ne.jp or.jp ac.jp co.kr or.kr
	com.br net.br org.br com.cn net.cn org.cn gov.cn com.hk com.tw com.sg com.my co.in net.in org.in
	co.za org.za com.mx com.ar com.tr com.ua com.pl co.il co.id com.ph com.vn com.sa com.eg
	gc.ca qc.ca on.ca bc.ca`) {
		multiSuffix[s] = true
	}
}
