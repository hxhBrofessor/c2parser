package engine

import (
	"runtime/debug"
	"runtime/metrics"
	"sync"
)

// Lean GC for big heaps (v9c 3.3). Go's default pacing lets the heap grow
// to twice the live set before collecting, so peak RSS ≈ 2 × live. Once an
// engine's live heap passes LeanGCBytes, the GC target drops to +50 % for
// the rest of that run: flow-heavy captures trade some CPU for a third
// less peak memory, while ordinary captures (live heap well below the
// threshold) run exactly as before. Shared by concurrent engines (-j).
var (
	LeanGCBytes uint64 = 512 << 20
	leanPercent        = 50
	// leanFinishPercent applies while a lean engine scores: Finish
	// allocates mostly short-lived garbage on top of the full live set.
	leanFinishPercent = 25

	leanMu    sync.Mutex
	leanUsers int
	leanPrev  int
)

var liveSample = []metrics.Sample{{Name: "/gc/heap/live:bytes"}}

// checkLeanGC switches this engine to lean GC when the live heap is big.
func (e *Engine) checkLeanGC() {
	if e.leanGC || LeanGCBytes == 0 {
		return
	}
	s := []metrics.Sample{liveSample[0]}
	metrics.Read(s)
	if s[0].Value.Kind() != metrics.KindUint64 || s[0].Value.Uint64() < LeanGCBytes {
		return
	}
	leanMu.Lock()
	defer leanMu.Unlock()
	if leanUsers == 0 {
		leanPrev = debug.SetGCPercent(leanPercent)
		if leanPrev < leanPercent && leanPrev > 0 { // user asked for leaner already
			debug.SetGCPercent(leanPrev)
		}
	}
	leanUsers++
	e.leanGC = true
}

// releaseLeanGC restores the GC target when the last lean engine finishes.
func (e *Engine) releaseLeanGC() {
	if !e.leanGC {
		return
	}
	leanMu.Lock()
	defer leanMu.Unlock()
	e.leanGC = false
	if leanUsers--; leanUsers == 0 {
		debug.SetGCPercent(leanPrev)
	}
}

// leanFinish tightens the GC target for the scoring phase of a lean
// engine; the returned func restores the ingest-phase target.
func (e *Engine) leanFinish() func() {
	if !e.leanGC {
		return func() {}
	}
	leanMu.Lock()
	prev := debug.SetGCPercent(leanFinishPercent)
	leanMu.Unlock()
	return func() {
		leanMu.Lock()
		debug.SetGCPercent(prev)
		leanMu.Unlock()
	}
}
