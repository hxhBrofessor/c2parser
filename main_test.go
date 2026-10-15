package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"c2parser/internal/engine"
	"c2parser/internal/report"
	"c2parser/internal/sigma"
	"c2parser/internal/synth"
)

// v9c 3.1: -j N gives byte-identical JSON to -j 1, in argument order.
func TestParallelIdentical(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for _, name := range []string{"shape-artifacts-http", "gate-fleet20", "shape-dns-txt-base32", "shape-smb-pipe-framed", "benign-models", "shape-https-proxy-connect"} {
		sc, err := synth.LoadScenario(filepath.Join("corpus/scenarios", name+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		me, err := synth.WriteFile(sc, dir)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, filepath.Join(dir, me.Path))
	}
	paths = append(paths, filepath.Join(dir, "missing.pcap")) // errors stay in place too
	render := func(jobs int, cfg engine.Config) string {
		var res []*engine.Result
		var b bytes.Buffer
		for _, r := range analyzeAll(paths, cfg, jobs) {
			if r.err != nil {
				b.WriteString("error:" + r.err.Error() + "\n")
				continue
			}
			res = append(res, r.res)
		}
		if err := report.JSON(&b, res, report.Options{MinScore: 0}); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	rules, _ := sigma.Load("rules/sigma")
	if len(rules) == 0 {
		t.Fatal("no built-in Sigma rules")
	}
	for _, cfg := range []engine.Config{{}, {TimingV2: true}, {Sigma: rules}, {TimingV2: true, Sigma: rules}} {
		one := render(1, cfg)
		for _, j := range []int{2, 4, 16} {
			if got := render(j, cfg); got != one {
				t.Errorf("v2=%v -j %d output differs from -j 1", cfg.TimingV2, j)
			}
		}
	}
}
