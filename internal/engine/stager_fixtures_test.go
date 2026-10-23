package engine

// Synthetic Cobalt Strike config fixtures for the B-4.4 S2 engine tap. These
// replicate ONLY the wire facts in internal/csconfig/FORMAT.md (the csconfig
// package's own test builders are not importable here, and the csconfig API
// must not be changed). All content is invented for tests; no real beacon
// material. A round-trip test (TestStagerFixturesCarve) proves the carver
// accepts these bytes, so the fixtures stay honest if the format shifts.

import (
	"encoding/binary"

	"c2parser/internal/csconfig"
)

var synthOID = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}

type synthSetting struct {
	index uint16
	typ   uint16
	value []byte
}

// sufficientSettings: SLEEPTIME + JITTER + PUBKEY(OID) + SUBMITURI (+ maxIndex)
// => structurally valid and evidence-sufficient (>=2 recognized non-PUBKEY
// incl. a timing setting).
func sufficientSettings(maxIndex uint16) []synthSetting {
	s := []synthSetting{
		{3, csconfig.TypeInt, []byte{0, 0, 0x27, 0x10}},                      // SLEEPTIME 10000
		{5, csconfig.TypeShort, []byte{0, 30}},                               // JITTER 30
		{7, csconfig.TypePtr, append([]byte{0x30, 0x81, 0x20}, synthOID...)}, // PUBKEY (OID)
		{10, csconfig.TypePtr, []byte("/submit.php")},                        // SUBMITURI
		{9, csconfig.TypePtr, []byte("Mozilla/5.0 (synthetic)")},             // USERAGENT
	}
	s = append(s, synthSetting{maxIndex, csconfig.TypeInt, []byte{0, 0, 0, byte(maxIndex)}})
	return s
}

// insufficientSettings: structurally valid (>=3 settings, PUBKEY with OID) but
// NOT evidence-sufficient (no SLEEPTIME/JITTER; only one recognized non-PUBKEY).
func insufficientSettings(maxIndex uint16) []synthSetting {
	s := []synthSetting{
		{7, csconfig.TypePtr, append([]byte{0x30, 0x81, 0x20}, synthOID...)}, // PUBKEY
		{10, csconfig.TypePtr, []byte("/x")},                                 // SUBMITURI (1 recognized)
	}
	s = append(s, synthSetting{maxIndex, csconfig.TypeInt, []byte{0, 0, 0, byte(maxIndex)}})
	return s
}

// makePlainStage builds an MZ container (MZ at 0, XOR'd settings block at 0x400).
func makePlainStage(patchSize int, key byte, settings []synthSetting) []byte {
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

// makeXorStage wraps a decoded stream in the rolling-nonce xorencoded wrapper.
func makeXorStage(decoded []byte, nonce [4]byte) []byte {
	out := make([]byte, 8+len(decoded))
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
	return out
}

func plainStageFixture() []byte {
	return makePlainStage(0x1800, 0x2e, sufficientSettings(76))
}

func xorStageFixture() []byte {
	plain := makePlainStage(0x1800, 0x2e, sufficientSettings(76))
	return makeXorStage(plain[2:], [4]byte{0x9a, 0xbc, 0xde, 0xf0})
}
