// Command synthgen writes synthetic captures from scenario YAML, plus a
// labels manifest in the `c2parser eval` format.
//
//	go run ./tools/synthgen -out corpus-out corpus/scenarios
//	c2parser eval -manifest corpus-out/manifest.yaml -out eval-out
//
// Every capture is a function of (scenario, seed): rerunning reproduces it
// byte for byte. Synthetic traffic tests c2parser against our own model of
// C2 and cannot set thresholds (docs/corpus.md).
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"c2parser/internal/pcapio"
	"c2parser/internal/synth"
)

func main() {
	out := flag.String("out", "corpus-out", "output directory")
	seed := flag.Uint64("seed", 0, "override every scenario's seed (0 = keep)")
	manifest := flag.String("manifest", "", "manifest path (default <out>/manifest.yaml)")
	zeek := flag.Bool("zeek", false, "also write <name>.conn.log (Zeek TSV, derived from the packets) and <name>.labels.jsonl (UID → c2|benign) per capture, for the eval zeek-uid label join")
	scale := flag.Int("scale", 0, "write the flow-heavy scale capture (N TCP one-shots + 0.4·N DNS + one periodic TLS series) to <out>/scale.pcap and exit")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: synthgen [-out dir] [-seed n] scenario.yaml|dir ...\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *scale > 0 {
		writeScale(*out, *scale)
		return
	}
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	var files []string
	for _, a := range flag.Args() {
		st, err := os.Stat(a)
		if err != nil {
			fatal(err)
		}
		if !st.IsDir() {
			files = append(files, a)
			continue
		}
		m, _ := filepath.Glob(filepath.Join(a, "*.yaml"))
		files = append(files, m...)
	}
	sort.Strings(files)
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fatal(err)
	}
	var rows []synth.ManifestEntry
	for _, f := range files {
		sc, err := synth.LoadScenario(f)
		if err != nil {
			fatal(fmt.Errorf("%s: %w", f, err))
		}
		if *seed != 0 {
			sc.Seed = *seed
		}
		me, err := synth.WriteFile(sc, *out)
		if err != nil {
			fatal(fmt.Errorf("%s: %w", f, err))
		}
		rows = append(rows, *me)
		if *zeek {
			if err := writeZeek(*out, me); err != nil {
				fatal(fmt.Errorf("%s: %w", f, err))
			}
		}
		fmt.Printf("%-40s seed=%-6d %s\n", me.Path, me.Seed, me.SHA256[:16])
	}
	mp := *manifest
	if mp == "" {
		mp = filepath.Join(*out, "manifest.yaml")
	}
	if err := synth.WriteManifest(mp, rows); err != nil {
		fatal(err)
	}
	fmt.Printf("%d captures → %s\n", len(rows), strings.TrimPrefix(mp, "./"))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "synthgen:", err)
	os.Exit(1)
}

func writeScale(dir string, n int) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fatal(err)
	}
	sc := synth.DefaultScale()
	sc.Conns, sc.DNS = n, n*2/5
	p := filepath.Join(dir, "scale.pcap")
	f, err := os.Create(p)
	if err != nil {
		fatal(err)
	}
	bw := bufio.NewWriterSize(f, 1<<20)
	info, err := synth.WriteScale(bw, sc)
	if err == nil {
		err = bw.Flush()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		fatal(err)
	}
	fmt.Printf("%s: %d packets, %d TCP connections, %d DNS pairs, periodic needle %s → %s (%s, %d events)\n",
		p, info.Packets, info.TCPConns, info.DNSPairs, sc.NeedleClient, sc.NeedleServer, sc.NeedleName, info.NeedleEvents)
}

// writeZeek derives a Zeek conn.log and a UID label file from a written
// capture (see synth.ZeekConns: independent of the engine).
func writeZeek(dir string, me *synth.ManifestEntry) error {
	r, err := pcapio.Open(filepath.Join(dir, me.Path))
	if err != nil {
		return err
	}
	conns, err := synth.ZeekConns(r)
	r.Close()
	if err != nil {
		return err
	}
	base := strings.TrimSuffix(strings.TrimSuffix(me.Path, ".pcapng"), ".pcap")
	var b, l bytes.Buffer
	if err := synth.WriteZeekTSV(&b, conns); err != nil {
		return err
	}
	if err := synth.WriteLabels(&l, synth.LabelConns(conns, me)); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, base+".conn.log"), b.Bytes(), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, base+".labels.jsonl"), l.Bytes(), 0o644)
}
