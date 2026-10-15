package synth

import (
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"time"
)

// Timing is a check-in schedule model. Sleep and the other durations are in
// seconds. C2-shaped models are named by their jitter polarity, never by
// framework:
//
//	fixed        gap = Sleep
//	shortening   gap = Sleep·(1 − J·u)          u ~ U[0,1]
//	lengthening  gap = Sleep·(1 + J·u)
//	symmetric    gap = Sleep·(1 + J·(2u − 1))
//	anchored     event k at k·Sleep + U[0, J·Sleep] (delay from a fixed grid)
//	lattice      symmetric, rounded to whole seconds
//	backoff      gap = Sleep·Factor^k, capped at Max, then back to Sleep
//
// Benign models (approximations for regression tests, not measurements):
//
//	poisson      exponential gaps, mean Sleep
//	gamma        gamma(Shape, Sleep/Shape) gaps
//	browsing     Poisson sessions (mean Sleep) of 5–30 requests 0.1–3 s apart
//	jamf         900 s ± 300 s
//	gpo          5400 s + U[0, 1800] s
//	wsus         79200 s × U[0.8, 1.0]
//	apt          12 h grid + U[0, 12 h] delay
//	chrony       Sleep (64…1024, power of two; default 1024) × U[1, 1.02]
//	prometheus   Sleep (default 15 s) ± 5 ms
//	wireguard    Sleep (default 25 s) ± 2 ms
//	intune       MDM ladder: 180 s ×5, 900 s ×8, then 28800 s × U[0.95, 1.05],
//	             15 % of those split by a push-triggered sync
//	chrome       18000 s + U[0, 60 s]; 10 % 21600 s + U[0, 60 s]
type Timing struct {
	Model  string  `yaml:"model" json:"model"`
	Sleep  float64 `yaml:"sleep" json:"sleep,omitempty"`
	Jitter float64 `yaml:"jitter" json:"jitter,omitempty"`
	Events int     `yaml:"events" json:"events"`
	Shape  float64 `yaml:"shape" json:"shape,omitempty"`   // gamma k
	Factor float64 `yaml:"factor" json:"factor,omitempty"` // backoff multiplier (default 2)
	Max    float64 `yaml:"max" json:"max,omitempty"`       // backoff cap (default 8·Sleep)
}

// Artifacts perturb a schedule the way real implants and operators do.
type Artifacts struct {
	// Missed is the probability that a check-in is skipped (the clock still
	// advances, so the next gap is a harmonic of the period).
	Missed float64 `yaml:"missed" json:"missed,omitempty"`
	// Tasking inserts Burst quick follow-up callbacks Gap seconds apart after
	// every Every-th check-in; RespBytes overrides their response size.
	Tasking *Tasking `yaml:"tasking" json:"tasking,omitempty"`
	// Stalls add extra silence after the given event index.
	Stalls []Stall `yaml:"stalls" json:"stalls,omitempty"`
	// SleepChange switches to a new sleep/jitter after event After.
	SleepChange *SleepChange `yaml:"sleep_change" json:"sleep_change,omitempty"`
	// WorkingHours keeps only events in [Start, End) UTC hours; events
	// outside move to the next Start.
	WorkingHours *Hours `yaml:"working_hours" json:"working_hours,omitempty"`
	// Second adds an independent second schedule on the same key (two
	// implants on one host talking to one destination).
	Second *Timing `yaml:"second_implant" json:"second_implant,omitempty"`
}

// Tasking is a burst of operator activity.
type Tasking struct {
	Every     int     `yaml:"every" json:"every"`
	Burst     int     `yaml:"burst" json:"burst"`
	Gap       float64 `yaml:"gap" json:"gap"`
	RespBytes int     `yaml:"resp_bytes" json:"resp_bytes,omitempty"`
}

// Stall is extra silence after an event.
type Stall struct {
	After   int     `yaml:"after" json:"after"`
	Seconds float64 `yaml:"seconds" json:"seconds"`
}

// SleepChange changes the schedule mid-session.
type SleepChange struct {
	After  int     `yaml:"after" json:"after"`
	Sleep  float64 `yaml:"sleep" json:"sleep"`
	Jitter float64 `yaml:"jitter" json:"jitter"`
}

// Hours is a UTC working-hours window.
type Hours struct {
	Start int `yaml:"start" json:"start"`
	End   int `yaml:"end" json:"end"`
}

// Event is one scheduled check-in. Tasking marks a follow-up inside a
// tasking burst.
type Event struct {
	At      time.Time
	Tasking bool
}

// Polarity is the jitter-polarity shape label for a model ("" when the
// model has none).
func (t Timing) Polarity() string {
	switch t.Model {
	case "shortening", "lengthening", "symmetric":
		return t.Model
	case "anchored":
		return "anchored"
	case "lattice":
		return "symmetric"
	}
	return ""
}

// Benign reports whether the model is one of the benign models.
func (t Timing) Benign() bool {
	switch t.Model {
	case "poisson", "gamma", "browsing", "jamf", "gpo", "wsus", "apt", "chrony", "prometheus", "wireguard", "intune", "chrome":
		return true
	}
	return false
}

// Validate checks the model name and parameters.
func (t Timing) Validate() error {
	switch t.Model {
	case "fixed", "shortening", "lengthening", "symmetric", "anchored", "lattice", "backoff", "poisson", "gamma", "browsing":
		if t.Sleep <= 0 {
			return fmt.Errorf("timing %s: sleep must be > 0", t.Model)
		}
	case "jamf", "gpo", "wsus", "apt", "chrony", "prometheus", "wireguard", "intune", "chrome":
	default:
		return fmt.Errorf("unknown timing model %q", t.Model)
	}
	if t.Events <= 0 {
		return fmt.Errorf("timing %s: events must be > 0", t.Model)
	}
	if t.Jitter < 0 || t.Jitter > 1 {
		return fmt.Errorf("timing %s: jitter must be in [0, 1]", t.Model)
	}
	if t.Model == "gamma" && t.Shape <= 0 {
		return fmt.Errorf("timing gamma: shape must be > 0")
	}
	return nil
}

// gap draws the k-th inter-event gap in seconds (k counts from 0).
func (t Timing) gap(r *rand.Rand, k int) float64 {
	S, J := t.Sleep, t.Jitter
	u := r.Float64()
	switch t.Model {
	case "fixed":
		return S
	case "shortening":
		return S * (1 - J*u)
	case "lengthening":
		return S * (1 + J*u)
	case "symmetric":
		return S * (1 + J*(2*u-1))
	case "lattice":
		return math.Max(1, math.Round(S*(1+J*(2*u-1))))
	case "backoff":
		f, mx := t.Factor, t.Max
		if f <= 1 {
			f = 2
		}
		if mx <= 0 {
			mx = 8 * S
		}
		// k-th gap of a cycle S, S·f, S·f², … ≤ mx, then repeats
		n := int(math.Floor(math.Log(mx/S)/math.Log(f))) + 1
		return S * math.Pow(f, float64(k%n))
	case "poisson":
		return S * r.ExpFloat64()
	case "gamma":
		return S / t.Shape * gammaVariate(r, t.Shape)
	case "jamf":
		return 900 + 600*(u-0.5)
	case "gpo":
		return 5400 + 1800*u
	case "wsus":
		return 79200 * (0.8 + 0.2*u)
	case "chrony":
		p := S
		if p == 0 {
			p = 1024
		}
		return p * (1 + 0.02*u)
	case "prometheus":
		p := S
		if p == 0 {
			p = 15
		}
		return p + 0.01*(u-0.5)
	case "wireguard":
		p := S
		if p == 0 {
			p = 25
		}
		return p + 0.004*(u-0.5)
	case "intune": // MDM ladder: 3 min ×5, 15 min ×8, then ~8 h, with push syncs
		switch {
		case k < 5:
			return 180 * (1 + 0.05*u)
		case k < 13:
			return 900 * (1 + 0.05*u)
		case r.Float64() < 0.15:
			return 28800 * (0.1 + 0.8*u) // push-triggered sync
		}
		return 28800 * (0.95 + 0.1*u)
	case "chrome": // browser updater: 5 h + U(0, 60 s), sometimes 6 h
		if r.Float64() < 0.1 {
			return 21600 + 60*u
		}
		return 18000 + 60*u
	}
	return S
}

// gammaVariate draws gamma(k, 1) (Marsaglia–Tsang; boosted for k < 1).
func gammaVariate(r *rand.Rand, k float64) float64 {
	if k < 1 {
		return gammaVariate(r, k+1) * math.Pow(r.Float64(), 1/k)
	}
	d := k - 1.0/3
	c := 1 / math.Sqrt(9*d)
	for {
		x := r.NormFloat64()
		v := 1 + c*x
		if v <= 0 {
			continue
		}
		v = v * v * v
		u := r.Float64()
		if math.Log(u) < 0.5*x*x+d-d*v+d*math.Log(v) {
			return d * v
		}
	}
}

// Schedule returns the event times for a model plus artifacts, starting at
// start (the first event is one gap after start). Same r state → same
// schedule.
func Schedule(start time.Time, t Timing, a Artifacts, r *rand.Rand) []Event {
	sec := func(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }
	var out []Event
	cur := t
	switch {
	case t.Model == "browsing":
		ts := start
		for len(out) < t.Events {
			ts = ts.Add(sec(t.Sleep * r.ExpFloat64()))
			n := 5 + r.IntN(26)
			for i := 0; i < n && len(out) < t.Events; i++ {
				out = append(out, Event{At: ts})
				ts = ts.Add(sec(0.1 + 2.9*r.Float64()))
			}
		}
	case t.Model == "anchored" || t.Model == "apt":
		grid, J := t.Sleep, t.Jitter
		if t.Model == "apt" {
			grid, J = 43200, 1
		}
		for k := 1; len(out) < t.Events; k++ {
			at := start.Add(sec(float64(k)*grid + J*grid*r.Float64()))
			if r.Float64() < a.Missed {
				continue
			}
			out = append(out, Event{At: at})
		}
	default:
		ts := start
		for k := 0; len(out) < t.Events; k++ {
			if sc := a.SleepChange; sc != nil && k == sc.After {
				cur.Sleep, cur.Jitter = sc.Sleep, sc.Jitter
			}
			ts = ts.Add(sec(cur.gap(r, k)))
			for _, st := range a.Stalls {
				if st.After == k {
					ts = ts.Add(sec(st.Seconds))
				}
			}
			if wh := a.WorkingHours; wh != nil {
				ts = intoHours(ts, wh)
			}
			if a.Missed > 0 && r.Float64() < a.Missed {
				continue
			}
			out = append(out, Event{At: ts})
			if tk := a.Tasking; tk != nil && tk.Every > 0 && len(out)%tk.Every == 0 {
				x := ts
				for i := 0; i < tk.Burst; i++ {
					x = x.Add(sec(tk.Gap))
					out = append(out, Event{At: x, Tasking: true})
				}
				ts = x
			}
		}
	}
	if a.Second != nil {
		s2 := *a.Second
		off := sec(s2.Sleep * r.Float64())
		out = append(out, Schedule(start.Add(off), s2, Artifacts{}, r)...)
		sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	}
	return out
}

// intoHours moves ts forward to the next working-hours window if needed.
func intoHours(ts time.Time, h *Hours) time.Time {
	hr := ts.UTC().Hour()
	if h.Start <= h.End {
		if hr >= h.Start && hr < h.End {
			return ts
		}
	} else if hr >= h.Start || hr < h.End { // window over midnight
		return ts
	}
	d := time.Date(ts.Year(), ts.Month(), ts.Day(), h.Start, 0, 0, 0, time.UTC)
	if !d.After(ts) {
		d = d.Add(24 * time.Hour)
	}
	return d.Add(ts.Sub(ts.Truncate(time.Minute))) // keep sub-minute phase
}
