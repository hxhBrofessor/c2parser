package engine

import "strings"

// counts is a string → count tally that keeps its first key inline and
// only allocates a map once a second distinct key appears (v9c 3.3). Most
// per-channel tallies (methods, User-Agents, SNI, JA3/JA4, ALPN) hold one
// key, and a one-entry Go map costs ~250 bytes; flow-heavy captures have a
// channel per connection.
type counts struct {
	k string
	n int
	m map[string]int // every key, once there is more than one
}

// inc adds one to k (copying k on first insert so a header block or packet
// buffer isn't pinned by a long-lived key).
func (c *counts) inc(k string) { c.add(k, 1) }

func (c *counts) add(k string, d int) {
	switch {
	case c.m != nil:
		if _, ok := c.m[k]; ok {
			c.m[k] += d
		} else {
			c.m[strings.Clone(k)] = d
		}
	case c.n == 0:
		c.k, c.n = strings.Clone(k), d
	case c.k == k:
		c.n += d
	default:
		c.m = map[string]int{c.k: c.n, strings.Clone(k): d}
		c.k, c.n = "", 0
	}
}

func (c *counts) len() int {
	if c == nil {
		return 0
	}
	if c.m != nil {
		return len(c.m)
	}
	if c.n > 0 {
		return 1
	}
	return 0
}

func (c *counts) get(k string) int {
	if c == nil {
		return 0
	}
	if c.m != nil {
		return c.m[k]
	}
	if c.n > 0 && c.k == k {
		return c.n
	}
	return 0
}

// Map returns the tally as a map (a fresh one-entry map for a single key;
// read-only use at scoring time).
func (c *counts) Map() map[string]int {
	if c == nil {
		return nil
	}
	if c.m != nil {
		return c.m
	}
	if c.n > 0 {
		return map[string]int{c.k: c.n}
	}
	return map[string]int{}
}
