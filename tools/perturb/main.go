// Command perturb rewrites a capture for stress testing: damage,
// encapsulation, re-addressing/cloning, re-timing one channel, splicing.
// Transforms chain in order; each writes a manifest row (JSON lines).
//
//	perturb -in lab.pcap -out x.pcap -t drop:p=0.01 -t wrap:kind=vxlan
//	perturb -in lab.pcap -out x.pcap \
//	    -t retime:client=10.0.0.5,server=203.0.113.9,port=80,model=shortening,sleep=60,jitter=0.2
//	perturb -in c2.pcap -out fleet.pcap -t clone:client=10.0.0.5,to=10.0.0.6+10.0.0.7,offset=7s
//	perturb -in background.pcap -out mix.pcap -t splice:file=c2.pcap,offset=300s
//
// Captures derived from lab pcaps stay outside the repo (docs/corpus.md).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"c2parser/internal/perturb"
	"c2parser/internal/synth"
)

type specs []string

func (s *specs) String() string     { return strings.Join(*s, " ") }
func (s *specs) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	in := flag.String("in", "", "input pcap/pcapng")
	out := flag.String("out", "", "output pcap")
	manifest := flag.String("manifest", "", "append one JSON line per transform to this file")
	seed := flag.Uint64("seed", 42, "default seed for random transforms")
	var ts specs
	flag.Var(&ts, "t", "transform name:key=value,... (repeatable; see -h)")
	flag.Usage = func() {
		o := flag.CommandLine.Output()
		fmt.Fprintln(o, "usage: perturb -in a.pcap -out b.pcap -t transform[:k=v,...] ...")
		fmt.Fprintln(o, `
transforms:
  drop:p=0.01  dup:p=0.01  reorder:p=0.01  snap:n=96  skip:frac=0.3  jitter:s=0.5
  conflict:p=0.01[,before=1]   oneway:dir=c2s|s2c
  wrap:kind=vlan|qinq|gre|erspan|vxlan
  readdress:map=10.0.0.5>10.9.0.5+203.0.113.9>198.51.100.9[,ports=443>8443]
  clone:client=IP,to=IP+IP,offset=7s
  redirect:server=IP,to=IP+IP+IP[,mode=round-robin|random]
  retime:client=IP,server=IP[,port=N],model=M,sleep=S[,jitter=J,missed=P,shape=K]
  splice:file=other.pcap,offset=300s
every random transform takes seed=N (default -seed)`)
		flag.PrintDefaults()
	}
	flag.Parse()
	if *in == "" || *out == "" || len(ts) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	pkts, err := perturb.Read(*in)
	if err != nil {
		fatal(err)
	}
	var rows []perturb.Change
	for _, spec := range ts {
		name, kv, err := parseSpec(spec)
		if err != nil {
			fatal(err)
		}
		sd := kv.u64("seed", *seed)
		var ch perturb.Change
		switch name {
		case "drop":
			pkts, ch = perturb.Drop(pkts, kv.f("p", 0.01), sd)
		case "dup":
			pkts, ch = perturb.Dup(pkts, kv.f("p", 0.01), sd)
		case "reorder":
			pkts, ch = perturb.Reorder(pkts, kv.f("p", 0.01), sd)
		case "snap":
			pkts, ch = perturb.Snap(pkts, int(kv.f("n", 96)))
		case "skip":
			pkts, ch = perturb.Skip(pkts, kv.f("frac", 0.3))
		case "jitter":
			pkts, ch = perturb.Jitter(pkts, kv.f("s", 0.5), sd)
		case "conflict":
			pkts, ch = perturb.Conflict(pkts, kv.f("p", 0.01), kv.f("before", 0) != 0, sd)
		case "oneway":
			pkts, ch, err = perturb.OneWay(pkts, kv.s("dir", "c2s"))
		case "wrap":
			pkts, ch, err = perturb.Wrap(pkts, kv.s("kind", "vlan"))
		case "readdress":
			m := perturb.AddrMap{IP: map[netip.Addr]netip.Addr{}, Port: map[uint16]uint16{}}
			for _, pair := range kv.list("map") {
				a, b, ok := strings.Cut(pair, ">")
				if !ok {
					fatal(fmt.Errorf("readdress: map entries are old>new"))
				}
				m.IP[addr(a)] = addr(b)
			}
			for _, pair := range kv.list("ports") {
				a, b, _ := strings.Cut(pair, ">")
				pa, _ := strconv.Atoi(a)
				pb, _ := strconv.Atoi(b)
				m.Port[uint16(pa)] = uint16(pb)
			}
			pkts, ch, err = perturb.Readdress(pkts, m)
		case "clone":
			pkts, ch, err = perturb.Clone(pkts, addr(kv.s("client", "")), addrs(kv.list("to")), kv.d("offset", 7*time.Second))
		case "redirect":
			pkts, ch, err = perturb.Redirect(pkts, addr(kv.s("server", "")), addrs(kv.list("to")), kv.s("mode", "round-robin"), sd)
		case "retime":
			c := perturb.Channel{Client: addr(kv.s("client", "")), Server: addr(kv.s("server", "")), Port: uint16(kv.f("port", 0))}
			m := synth.Timing{Model: kv.s("model", "shortening"), Sleep: kv.f("sleep", 60), Jitter: kv.f("jitter", 0), Shape: kv.f("shape", 0)}
			pkts, ch, err = perturb.Retime(pkts, c, m, synth.Artifacts{Missed: kv.f("missed", 0)}, sd)
		case "splice":
			add, rerr := perturb.Read(kv.s("file", ""))
			if rerr != nil {
				fatal(rerr)
			}
			pkts, ch, err = perturb.Splice(pkts, add, kv.d("offset", 0))
		default:
			fatal(fmt.Errorf("unknown transform %q", name))
		}
		if err != nil {
			fatal(err)
		}
		rows = append(rows, ch)
		fmt.Fprintf(os.Stderr, "%-9s in=%d out=%d changed=%d %s\n", ch.Transform, ch.In, ch.Out, ch.Changed, ch.Detail)
	}
	if err := perturb.Write(*out, pkts); err != nil {
		fatal(err)
	}
	if *manifest != "" {
		f, err := os.OpenFile(*manifest, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			fatal(err)
		}
		enc := json.NewEncoder(f)
		for _, r := range rows {
			if err := enc.Encode(struct {
				In  string `json:"in"`
				Out string `json:"out"`
				perturb.Change
			}{*in, *out, r}); err != nil {
				fatal(err)
			}
		}
		f.Close()
	}
}

type kvs map[string]string

func parseSpec(s string) (string, kvs, error) {
	name, rest, _ := strings.Cut(s, ":")
	kv := kvs{}
	if rest != "" {
		for _, part := range strings.Split(rest, ",") {
			k, v, ok := strings.Cut(part, "=")
			if !ok {
				return "", nil, fmt.Errorf("%s: %q is not key=value", name, part)
			}
			kv[k] = v
		}
	}
	return name, kv, nil
}

func (kv kvs) s(k, d string) string {
	if v, ok := kv[k]; ok {
		return v
	}
	return d
}

func (kv kvs) f(k string, d float64) float64 {
	v, ok := kv[k]
	if !ok {
		return d
	}
	x, err := strconv.ParseFloat(v, 64)
	if err != nil {
		fatal(fmt.Errorf("%s=%q: %w", k, v, err))
	}
	return x
}

func (kv kvs) u64(k string, d uint64) uint64 {
	v, ok := kv[k]
	if !ok {
		return d
	}
	x, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		fatal(fmt.Errorf("%s=%q: %w", k, v, err))
	}
	return x
}

func (kv kvs) d(k string, d time.Duration) time.Duration {
	v, ok := kv[k]
	if !ok {
		return d
	}
	x, err := time.ParseDuration(v)
	if err != nil {
		fatal(fmt.Errorf("%s=%q: %w", k, v, err))
	}
	return x
}

func (kv kvs) list(k string) []string {
	if v := kv[k]; v != "" {
		return strings.Split(v, "+")
	}
	return nil
}

func addr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		fatal(fmt.Errorf("address %q: %w", s, err))
	}
	return a
}

func addrs(ss []string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, addr(s))
	}
	return out
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "perturb:", err)
	os.Exit(1)
}
