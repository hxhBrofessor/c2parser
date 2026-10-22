// Synthetic fixtures below encode only wire facts in FORMAT.md; all payload content is invented for tests.
package csconfig

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

type syntheticSetting struct {
	index uint16
	typ   uint16
	value []byte
}

var syntheticOID = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}

func fixtureSettings(maxIndex uint16) []syntheticSetting {
	settings := []syntheticSetting{
		{index: 3, typ: TypeInt, value: []byte{0, 0, 0x27, 0x10}},
		{index: 5, typ: TypeShort, value: []byte{0, 30}},
		{index: 7, typ: TypePtr, value: append([]byte{0x30, 0x81, 0x20}, syntheticOID...)},
		{index: 10, typ: TypePtr, value: []byte("/stage")},
	}
	if maxIndex == 74 {
		settings = append(settings, syntheticSetting{index: 74, typ: TypePtr, value: []byte("mask")})
	} else {
		settings = append(settings, syntheticSetting{index: maxIndex, typ: TypeInt, value: []byte{0, 0, 0, byte(maxIndex)}})
	}
	return settings
}

func makePlainFixture(patchSize int, key byte, settings []syntheticSetting) []byte {
	block := make([]byte, patchSize)
	pos := 0
	for _, s := range settings {
		binary.BigEndian.PutUint16(block[pos:pos+2], s.index)
		binary.BigEndian.PutUint16(block[pos+2:pos+4], s.typ)
		binary.BigEndian.PutUint16(block[pos+4:pos+6], uint16(len(s.value)))
		copy(block[pos+6:], s.value)
		pos += 6 + len(s.value)
	}
	pos += 6 // zero-index terminator
	for i := range block {
		block[i] ^= key
	}
	container := make([]byte, 0x400+len(block))
	copy(container, []byte{'M', 'Z'})
	copy(container[0x400:], block)
	return container
}

func makeXorEncodedFixture(decoded []byte, nonce [4]byte, trailer int) []byte {
	out := make([]byte, 8+len(decoded)+trailer)
	copy(out[:4], nonce[:])
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(decoded)))
	for i := 0; i < 4; i++ {
		out[4+i] ^= nonce[i]
	}
	for i, b := range decoded {
		prior := nonce[i%4]
		if i >= 4 {
			prior = out[8+i-4]
		}
		out[8+i] = b ^ prior
	}
	for i := 0; i < trailer; i++ {
		out[8+len(decoded)+i] = 0xa5
	}
	return out
}

func feedAndResult(data []byte, opts Options) (*Config, *Carver, bool) {
	c := New(opts)
	c.Feed(data)
	got, ok := c.Result()
	return got, c, ok
}

func settingNamed(c *Config, name string) (Setting, bool) {
	for _, s := range c.Settings {
		if s.Name == name {
			return s, true
		}
	}
	return Setting{}, false
}

func TestG41PlainConfigRecoversPassiveSettings(t *testing.T) {
	fixture := makePlainFixture(0x1800, 0x2e, fixtureSettings(76))
	got, c, ok := feedAndResult(fixture, Options{})
	defer c.Close()
	if !ok {
		t.Fatalf("carve failed: %s", c.Reason())
	}
	if got.PatchSize != 0x1800 || got.XORKey != 0x2e || got.XorEncoded {
		t.Fatalf("unexpected config metadata: %+v", got)
	}
	for name, want := range map[string]uint64{"SLEEPTIME": 10000, "JITTER": 30} {
		s, found := settingNamed(got, name)
		if !found || !s.HasNumber || s.Number != want {
			t.Errorf("%s = %+v, found=%v; want %d", name, s, found, want)
		}
	}
	s, found := settingNamed(got, "SUBMITURI")
	if !found || !bytes.Equal(s.Raw, []byte("/stage")) {
		t.Errorf("SUBMITURI = %+v, found=%v", s, found)
	}
}

func TestPatchSize1000Variant(t *testing.T) {
	fixture := makePlainFixture(0x1000, 0x2e, fixtureSettings(74))
	got, c, ok := feedAndResult(fixture, Options{})
	defer c.Close()
	if !ok {
		t.Fatalf("carve failed: %s", c.Reason())
	}
	if got.PatchSize != 0x1000 || got.Version != "≈ CS 4.7" {
		t.Fatalf("patch/version = %x/%q", got.PatchSize, got.Version)
	}
}

func TestG42FallbackSingleByteKey(t *testing.T) {
	fixture := makePlainFixture(0x1800, 0x43, fixtureSettings(76))
	got, c, ok := feedAndResult(fixture, Options{})
	defer c.Close()
	if !ok || got.XORKey != 0x43 {
		t.Fatalf("fallback carve = %+v, reason=%s, ok=%v", got, c.Reason(), ok)
	}
}

func TestG43XorEncodedWrapper(t *testing.T) {
	plain := makePlainFixture(0x1800, 0x2e, fixtureSettings(76))
	wrapped := makeXorEncodedFixture(plain, [4]byte{0x12, 0x34, 0x56, 0x78}, 17)
	got, c, ok := feedAndResult(wrapped, Options{})
	defer c.Close()
	if !ok || !got.XorEncoded {
		t.Fatalf("xorencoded carve = %+v, reason=%s, ok=%v", got, c.Reason(), ok)
	}
	withoutMZ := makeXorEncodedFixture(plain[2:], [4]byte{0x9a, 0xbc, 0xde, 0xf0}, 0)
	got, c2, ok := feedAndResult(withoutMZ, Options{})
	defer c2.Close()
	if !ok || !got.XorEncoded {
		t.Fatalf("xorencoded stage without MZ check = %+v, reason=%s, ok=%v", got, c2.Reason(), ok)
	}
}

func TestG44FalseCarveGuards(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "OID outside settings", data: append(bytes.Repeat([]byte{0x90}, 80), syntheticOID...)},
		{name: "random TLV-shaped noise", data: bytes.Repeat([]byte{0, 1, 0, 3, 0, 4, 1, 2, 3, 4}, 128)},
		{name: "truncated setting", data: makePlainFixture(0x1800, 0x2e, fixtureSettings(76))[:0x400+30]},
		{name: "wrong key and damaged anchor", data: func() []byte {
			b := makePlainFixture(0x1800, 0x2e, fixtureSettings(76))
			b[0x400+10+8+6+3+1] ^= 0x01
			return b
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, c, ok := feedAndResult(tt.data, Options{})
			defer c.Close()
			if ok || got != nil || c.Reason() == "" {
				t.Fatalf("expected explicit NOT_CARVED, got=%+v reason=%q ok=%v", got, c.Reason(), ok)
			}
		})
	}
}

func TestXorEncodedNearMissesAndOutOfScopeReason(t *testing.T) {
	short := makeXorEncodedFixture(bytes.Repeat([]byte{0x5a}, 0x1ff), [4]byte{1, 2, 3, 4}, 0)
	longTrailer := makeXorEncodedFixture(bytes.Repeat([]byte{0x5a}, 0x200), [4]byte{5, 6, 7, 8}, 257)
	for name, data := range map[string][]byte{"decoded size below minimum": short, "trailer above limit": longTrailer, "unknown wrapper": append([]byte("OBF!"), bytes.Repeat([]byte{0x42}, 1200)...)} {
		t.Run(name, func(t *testing.T) {
			got, c, ok := feedAndResult(data, Options{})
			defer c.Close()
			if ok || got != nil || c.Reason() == "" {
				t.Fatalf("expected NOT_CARVED reason, got=%+v reason=%q ok=%v", got, c.Reason(), ok)
			}
		})
	}
}

func TestDefaultKeyPrecedesFallbackWhenBothCarve(t *testing.T) {
	fallback := makePlainFixture(0x1800, 0x43, fixtureSettings(76))
	preferred := makePlainFixture(0x1800, 0x2e, fixtureSettings(76))
	got, c, ok := feedAndResult(append(fallback, preferred...), Options{})
	defer c.Close()
	if !ok || got.XORKey != 0x2e {
		t.Fatalf("default key should outrank fallback: config=%+v ok=%v reason=%q", got, ok, c.Reason())
	}
}

func TestVersionAnnotationAndEmptyMap(t *testing.T) {
	got, c, ok := feedAndResult(makePlainFixture(0x1800, 0x2e, fixtureSettings(76)), Options{})
	defer c.Close()
	if !ok || got.Version != "≈ CS 4.9" || got.VersionAnnotation != "max setting index 76 (≈ CS 4.9 per dissect.cobaltstrike v1.3.0)" {
		t.Fatalf("index 76 version = %q, ok=%v", got.Version, ok)
	}
	got, c2, ok := feedAndResult(makePlainFixture(0x1800, 0x2e, fixtureSettings(76)), Options{VersionMap: map[uint16]string{}})
	defer c2.Close()
	if !ok || got.Version != "unknown" {
		t.Fatalf("empty version map = %q, ok=%v", got.Version, ok)
	}
}

func TestReusedIndexDisambiguation(t *testing.T) {
	cases := []struct {
		name, want string
		index, typ uint16
		max        uint16
	}{
		{"16-old", "KILLDATE_YEAR", 16, TypeShort, 73},
		{"16-new", "BOF_ALLOCATOR", 16, TypeShort, 76},
		{"17-short", "KILLDATE_MONTH", 17, TypeShort, 76},
		{"17-int", "SYSCALL_METHOD", 17, TypeInt, 76},
		{"36-short", "INJECT_OPTIONS", 36, TypeShort, 76},
		{"36-ptr", "WATERMARKHASH", 36, TypePtr, 76},
		{"48-old", "PROCINJ_ALLOWED", 48, TypeShort, 73},
		{"48-new", "PROCINJ_BOF_REUSE_MEM", 48, TypeShort, 74},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			settings := append(fixtureSettings(tc.max), syntheticSetting{index: tc.index, typ: tc.typ, value: []byte{1, 2}})
			fixture := makePlainFixture(0x1800, 0x2e, settings)
			got, c, ok := feedAndResult(fixture, Options{})
			defer c.Close()
			if !ok {
				t.Fatalf("carve failed: %s", c.Reason())
			}
			if _, found := settingNamed(got, tc.want); !found {
				t.Fatalf("missing resolved name %s in %+v", tc.want, got.Settings)
			}
		})
	}
}

func TestTerminatorAndUnexpectedLength(t *testing.T) {
	settings := fixtureSettings(76)
	fixture := makePlainFixture(0x1800, 0x2e, settings)
	terminatorOffset := 0
	for _, item := range settings {
		terminatorOffset += 6 + len(item.value)
	}
	afterTerminator := []byte{0, 12, 0, byte(TypePtr), 0, 1, 'x'}
	for i := range afterTerminator {
		afterTerminator[i] ^= 0x2e
	}
	copy(fixture[0x400+terminatorOffset+6:], afterTerminator)
	got, c, ok := feedAndResult(fixture, Options{})
	defer c.Close()
	if !ok {
		t.Fatalf("carve failed: %s", c.Reason())
	}
	if _, found := settingNamed(got, "C2_REQUEST"); found {
		t.Fatal("parser consumed bytes after the index-zero terminator")
	}
	bad := append(fixtureSettings(76), syntheticSetting{index: 12, typ: TypeInt, value: []byte{1, 2, 3}})
	fixture = makePlainFixture(0x1800, 0x2e, bad)
	got, c2, ok := feedAndResult(fixture, Options{})
	defer c2.Close()
	if !ok {
		t.Fatalf("carve failed: %s", c2.Reason())
	}
	s, found := settingNamed(got, "C2_REQUEST")
	if !found || !s.UnexpectedLength || !bytes.Equal(s.Raw, []byte{1, 2, 3}) {
		t.Fatalf("unexpected-length setting = %+v found=%v", s, found)
	}
}

func TestFallbackOrderIsDeterministic(t *testing.T) {
	window := append(bytes.Repeat([]byte{0x41}, 12), bytes.Repeat([]byte{0x42}, 12)...)
	first := fallbackOrder(window)
	second := fallbackOrder(append([]byte(nil), window...))
	if !bytes.Equal(first, second) {
		t.Fatalf("fallback order changed: %v vs %v", first, second)
	}
	if len(first) != 253 || first[0] != 0x41 || first[1] != 0x42 {
		t.Fatalf("unexpected fallback ranking: len=%d first=%v", len(first), first[:2])
	}
}

func TestRetainedWindowAndConcurrentCarverLimit(t *testing.T) {
	c := New(Options{})
	defer c.Close()
	c.Feed(bytes.Repeat([]byte{0x5a}, 32<<20))
	if c.RetainedBytes() > 3*0x1800 || cap(c.buffer) > 3*0x1800 {
		t.Fatalf("retained=%d capacity=%d; cap=%d", c.RetainedBytes(), cap(c.buffer), 3*0x1800)
	}
	limiter := NewLimiter(32)
	carvers := make([]*Carver, 0, 33)
	for i := 0; i < 33; i++ {
		carvers = append(carvers, New(Options{Limiter: limiter}))
	}
	defer func() {
		for _, item := range carvers {
			item.Close()
		}
	}()
	if carvers[32].Reason() != ReasonResourceLimit {
		t.Fatalf("33rd carver reason = %q", carvers[32].Reason())
	}
}

func FuzzCSConfigCarve(f *testing.F) {
	f.Add([]byte("MZ"))
	f.Add(makePlainFixture(0x1000, 0x2e, fixtureSettings(74)))
	f.Fuzz(func(t *testing.T, data []byte) {
		c := New(Options{})
		defer c.Close()
		c.Feed(data)
		_, _ = c.Result()
		if c.RetainedBytes() > 3*0x1800 {
			t.Fatalf("retained %d bytes", c.RetainedBytes())
		}
	})
}

func TestSyntheticFixtureShape(t *testing.T) {
	fixture := makePlainFixture(0x1000, 0x2e, fixtureSettings(74))
	if string(fixture[:2]) != "MZ" || len(fixture) != 0x1400 {
		t.Fatalf("bad synthetic PE-shaped container: len=%d", len(fixture))
	}
	if got := fmt.Sprintf("%x", syntheticOID); got != "06092a864886f70d010101" {
		t.Fatalf("unexpected synthetic anchor bytes %s", got)
	}
}
