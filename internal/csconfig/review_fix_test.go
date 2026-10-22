package csconfig

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func reviewFeed(c *Carver, data []byte, chunks []int) {
	for i := 0; len(data) > 0; i++ {
		n := chunks[i%len(chunks)]
		if n > len(data) {
			n = len(data)
		}
		c.Feed(data[:n])
		data = data[n:]
	}
}

func TestReviewXorEncodedLargeStreamsAndOffsets(t *testing.T) {
	for _, size := range []int{24 << 10, 64 << 10, 300 << 10, 1 << 20} {
		for _, offset := range []int{0, 7, 1023} {
			t.Run(fmtReview(size, offset), func(t *testing.T) {
				plain := makePlainFixture(0x1800, 0x2e, fixtureSettings(76))
				decoded := make([]byte, size)
				copy(decoded, plain)
				trailer := 128
				if size == 24<<10 && offset == 0 {
					trailer = 0
				} else if size == 24<<10 && offset == 7 {
					trailer = wrapperMaximumSlack
				}
				wrapped := append(bytes.Repeat([]byte{0x55}, offset), makeXorEncodedFixture(decoded, [4]byte{1, 2, 3, 4}, trailer)...)
				c := New(Options{Limiter: NewLimiter(2)})
				chunks := []int{4096, 4096, 4103}
				if size == 24<<10 && offset == 7 {
					chunks = []int{1}
				} else if size == 24<<10 && offset == 1023 {
					chunks = []int{4093, 1, 17}
				}
				reviewFeed(c, wrapped, chunks)
				got, ok := c.Result()
				defer c.Close()
				if !ok || got == nil || !got.XorEncoded {
					t.Fatalf("size=%d offset=%d: got=%+v reason=%q", size, offset, got, c.Reason())
				}
			})
		}
	}
}

func fmtReview(size, offset int) string {
	return fmt.Sprintf("size_%d_offset_%d", size, offset)
}

func TestReviewExactNotCarvedReasons(t *testing.T) {
	r4k := make([]byte, 4096)
	rand.New(rand.NewSource(2)).Read(r4k)
	r1m := make([]byte, 1<<20)
	rand.New(rand.NewSource(3)).Read(r1m)
	oidNoise := bytes.Repeat(syntheticOID, 8)
	for _, tc := range []struct {
		name string
		data []byte
		want Reason
	}{
		{"random_4k", r4k, ReasonNoAnchor},
		{"random_1m", r1m, ReasonNoAnchor},
		{"zeros", make([]byte, 4096), ReasonNoAnchor},
		{"oid_only", oidNoise, ReasonAnchorWithoutValidConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(Options{Limiter: NewLimiter(2)})
			reviewFeed(c, tc.data, []int{4096})
			_, ok := c.Result()
			defer c.Close()
			if ok || c.Reason() != tc.want {
				t.Fatalf("reason=%q ok=%v want=%q", c.Reason(), ok, tc.want)
			}
		})
	}
}

func TestReviewXorEncodedNearMissReasons(t *testing.T) {
	short := makeXorEncodedFixture(bytes.Repeat([]byte{0x5a}, 0x1ff), [4]byte{1, 2, 3, 4}, 0)
	plain := makePlainFixture(0x1800, 0x2e, fixtureSettings(76))
	tooMuchTrailer := makeXorEncodedFixture(plain, [4]byte{5, 6, 7, 8}, 257)
	for _, tc := range []struct {
		name string
		data []byte
		want Reason
	}{
		{"decoded_size_below_minimum", short, ReasonNoAnchor},
		{"trailer_257", tooMuchTrailer, ReasonInvalidStage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(Options{Limiter: NewLimiter(2)})
			reviewFeed(c, tc.data, []int{4096, 4103})
			_, ok := c.Result()
			defer c.Close()
			if ok || c.Reason() != tc.want {
				t.Fatalf("reason=%q ok=%v want=%q", c.Reason(), ok, tc.want)
			}
		})
	}
	// A decoded, anchored config outside [offset+12, end) invalidates the candidate.
	if valid, invalid := validateWrappedConfig(wrapperCandidate{offset: 1023, size: 0x200}, 64, 128, 4096); valid || !invalid {
		t.Fatalf("outside config validation = valid:%v invalid:%v", valid, invalid)
	}
	if valid, invalid := validateWrappedConfig(wrapperCandidate{offset: 0, size: 0x1800 + 24}, 32, 32+0x1800, 0x1800+24+8+128); !valid || invalid {
		t.Fatalf("inside config validation = valid:%v invalid:%v", valid, invalid)
	}
	if valid, invalid := validateWrappedConfig(wrapperCandidate{offset: 0, size: 0x1800 + 24}, 32, 32+0x1800, 0x1800+24+8+257); valid || !invalid {
		t.Fatalf("excess trailer validation = valid:%v invalid:%v", valid, invalid)
	}
}

func TestReviewWorkBudgetBoundsOIDDenseInput(t *testing.T) {
	data := bytes.Repeat(syntheticOID, (1<<20)/len(syntheticOID)+1)[:1<<20]
	c := New(Options{Limiter: NewLimiter(2)})
	reviewFeed(c, data, []int{4096})
	_, ok := c.Result()
	defer c.Close()
	if ok || c.Reason() != ReasonWorkBudgetExhausted {
		t.Fatalf("reason=%q ok=%v", c.Reason(), ok)
	}
	if c.workUsed > maxCarveWork {
		t.Fatalf("work=%d exceeds budget=%d", c.workUsed, maxCarveWork)
	}
}

func TestReviewWorkBudgetBoundsDerivedOIDDenseInput(t *testing.T) {
	derived := make([]byte, 1<<20)
	for i := range derived {
		derived[i] = syntheticOID[i%len(syntheticOID)]
	}
	ciphertext := make([]byte, len(derived))
	for i, value := range derived {
		if i >= wrapperNonceSize {
			value ^= ciphertext[i-wrapperNonceSize]
		}
		ciphertext[i] = value
	}
	c := New(Options{Limiter: NewLimiter(2)})
	reviewFeed(c, ciphertext, []int{4096})
	_, ok := c.Result()
	defer c.Close()
	if ok || c.Reason() != ReasonWorkBudgetExhausted {
		t.Fatalf("reason=%q ok=%v", c.Reason(), ok)
	}
	if c.workUsed > maxCarveWork {
		t.Fatalf("work=%d exceeds budget=%d", c.workUsed, maxCarveWork)
	}
}

func TestReviewWorkBudgetTimingGate(t *testing.T) {
	const size = 1 << 20
	randomPlain := make([]byte, size)
	rand.New(rand.NewSource(17)).Read(randomPlain)
	densePlain := bytes.Repeat(syntheticOID, size/len(syntheticOID)+1)[:size]
	toCipher := func(derived []byte) []byte {
		out := make([]byte, len(derived))
		for i, value := range derived {
			if i >= wrapperNonceSize {
				value ^= out[i-wrapperNonceSize]
			}
			out[i] = value
		}
		return out
	}
	run := func(name string, data []byte) (time.Duration, int) {
		c := New(Options{Limiter: NewLimiter(2)})
		start := time.Now()
		reviewFeed(c, data, []int{4096})
		c.Result()
		elapsed, work := time.Since(start), c.workUsed
		c.Close()
		t.Logf("%s elapsed=%s work=%d reason=%s", name, elapsed, work, c.Reason())
		return elapsed, work
	}
	plainRandomTime, _ := run("plain_random_1m", randomPlain)
	plainDenseTime, plainWork := run("plain_oid_dense_1m", densePlain)
	derivedRandomTime, _ := run("derived_random_1m", randomPlain)
	derivedDenseTime, derivedWork := run("derived_oid_dense_1m", toCipher(densePlain))
	if plainWork > maxCarveWork || derivedWork > maxCarveWork {
		t.Fatalf("work exceeded budget: plain=%d derived=%d limit=%d", plainWork, derivedWork, maxCarveWork)
	}
	// Wall times are reported for the separate G-4.5b gate; unit assertions
	// cover only deterministic work counters.
	_ = [4]time.Duration{plainRandomTime, plainDenseTime, derivedRandomTime, derivedDenseTime}
}

func TestReviewLimiterReleasedByClose(t *testing.T) {
	l := NewLimiter(1)
	c := New(Options{Limiter: l})
	c.Close()
	next := New(Options{Limiter: l})
	defer next.Close()
	if next.Reason() == ReasonResourceLimit {
		t.Fatal("Close did not release limiter slot")
	}
}

func TestReviewPubkeyMustBePointer(t *testing.T) {
	settings := fixtureSettings(76)
	for i := range settings {
		if settings[i].index == settingIndexPubKey {
			settings[i].typ = TypeShort
		}
	}
	c := New(Options{Limiter: NewLimiter(2)})
	c.Feed(makePlainFixture(0x1800, 0x2e, settings))
	_, ok := c.Result()
	defer c.Close()
	if ok {
		t.Fatal("accepted non-pointer PUBKEY")
	}
}
