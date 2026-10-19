package synth

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseScenario: arbitrary YAML never panics the parser, and anything
// it accepts generates without panicking (events capped to stay fast).
func FuzzParseScenario(f *testing.F) {
	files, _ := filepath.Glob("../../corpus/scenarios/*.yaml")
	for _, p := range files {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		sc, err := ParseScenario(b)
		if err != nil {
			return
		}
		for i := range sc.Streams {
			st := &sc.Streams[i]
			st.Timing.Events = min(st.Timing.Events, 50)
			if st.Topology.Fleet != nil {
				st.Topology.Fleet.N = min(st.Topology.Fleet.N, 4)
			}
			if st.Artifacts.Second != nil {
				st.Artifacts.Second.Events = min(st.Artifacts.Second.Events, 20)
			}
			if tk := st.Artifacts.Tasking; tk != nil {
				tk.Burst = min(tk.Burst, 5)
			}
			for _, sz := range []*Size{&st.Content.Poll, &st.Content.Resp} {
				sz.Min, sz.Max, sz.Mean = min(sz.Min, 4096), min(sz.Max, 4096), min(sz.Mean, 4096)
			}
			st.Content.Pad[1] = min(st.Content.Pad[1], 256)
			if st.Content.XORKey > 64 {
				st.Content.XORKey = 64
			}
			if st.Timing.Sleep > 1e6 {
				st.Timing.Sleep = 1e6
			}
		}
		_, _ = Generate(sc, io.Discard)
	})
}
