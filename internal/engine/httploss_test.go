package engine

import (
	mrand "math/rand/v2"
	"testing"
	"time"
)

func seededBytes(r *mrand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.IntN(256))
	}
	return b
}

// v9 Phase 1.4 gate: after a TCP gap the HTTP parser resyncs on the next
// request/status line at any offset. Recovered messages ≥ 95 % of the
// messages with no dropped segment, and recovery is monotonically
// non-increasing in the loss rate.
func TestHTTPRecoveryUnderLoss(t *testing.T) {
	prev := 1 << 30
	for _, p := range []float64{0, 0.001, 0.01, 0.05} {
		s := newSynth(t)
		r := mrand.New(mrand.NewPCG(5, 5))
		body := mrand.New(mrand.NewPCG(6, 6))
		ts := s.now
		c := s.tcp(ts, "10.40.0.5", 55000, "203.0.113.140", 80)
		c.Drop = func() bool { return r.Float64() < p }
		intact := 0
		for i := 0; i < 400; i++ {
			ts = ts.Add(3 * time.Second)
			d0 := c.Dropped
			ts = c.Send(ts, true, httpReq("POST", "/x", []string{"Host: a.example"}, string(seededBytes(body, 900))), 400)
			d1 := c.Dropped
			ts = c.Send(ts.Add(30*time.Millisecond), false, httpResp("HTTP/1.1 200 OK", []string{"Content-Type: application/octet-stream"}, string(seededBytes(body, 700))), 400)
			if d1 == d0 {
				intact++
			}
			if c.Dropped == d1 {
				intact++
			}
		}
		c.Close(ts.Add(time.Second))
		got := s.analyze(Config{}).Counters.HTTPMessages
		if float64(got) < 0.95*float64(intact) {
			t.Errorf("loss %.1f%%: %d messages recovered, %d intact (want ≥ 95%%)", p*100, got, intact)
		}
		if got > prev {
			t.Errorf("loss %.1f%%: recovery %d > %d at lower loss (not monotonic)", p*100, got, prev)
		}
		prev = got
	}
}
