package csconfig

import (
	"bytes"
	"encoding/binary"
	"sort"
	"sync"
)

// Numeric format constants are documented in FORMAT.md under setting block,
// anchor/patch sizes, xorencoded wrapper, and design decisions.
const (
	maxPatchSize         = 0x1800
	oldPatchSize         = 0x1000
	maxRetainedWindow    = 3 * maxPatchSize
	wrapperNonceSize     = 4
	wrapperHeaderSize    = 8
	wrapperScanLimit     = 1024
	wrapperMinimumSize   = 0x200
	wrapperMaximumSlack  = 256
	maxConcurrentCarvers = 32
)

// Default key values and OID bytes are cited in FORMAT.md, "Anchor, patch sizes, and XOR keys".
var (
	defaultXORKeys   = [...]byte{0x69, 0x2e, 0x00}
	rsaEncryptionOID = [...]byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}
)

// Carve reasons are the explicit NOT_CARVED outcomes required by FORMAT.md and the WS-4 order.
type Reason string

const (
	ReasonNone          Reason = ""
	ReasonNoAnchor      Reason = "no_anchor"
	ReasonInvalidConfig Reason = "invalid_or_truncated_config"
	ReasonInvalidStage  Reason = "invalid_xorencoded_wrapper"
	ReasonResourceLimit Reason = "resource_limit"
	ReasonOutOfScope    Reason = "out_of_scope_wrapper"
)

// Limiter caps concurrent standalone carvers without an engine dependency.
type Limiter struct {
	mu     sync.Mutex
	limit  int
	active int
}

func NewLimiter(limit int) *Limiter {
	if limit <= 0 {
		limit = maxConcurrentCarvers
	}
	return &Limiter{limit: limit}
}

func (l *Limiter) acquire() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active >= l.limit {
		return false
	}
	l.active++
	return true
}

func (l *Limiter) release() {
	l.mu.Lock()
	if l.active > 0 {
		l.active--
	}
	l.mu.Unlock()
}

var processLimiter = NewLimiter(maxConcurrentCarvers)

// Options controls version annotation and optional shared concurrency limiting.
type Options struct {
	VersionMap map[uint16]string
	Limiter    *Limiter
}

type anchorCandidate struct {
	absolute int64
	key      byte
}

// Carver keeps only a bounded rolling input window and stores parsed results, never payload logs.
type Carver struct {
	mu         sync.Mutex
	options    Options
	versions   map[uint16]string
	limiter    *Limiter
	admitted   bool
	closed     bool
	total      int64
	buffer     []byte
	overlap    []byte
	pending    []anchorCandidate
	config     *Config
	reason     Reason
	badWrapper bool
}

func New(opts Options) *Carver {
	versions := opts.VersionMap
	if versions == nil {
		versions = embeddedVersionMap()
	} else {
		versions = cloneVersionMap(versions)
	}
	limiter := opts.Limiter
	if limiter == nil {
		limiter = processLimiter
	}
	c := &Carver{versions: versions, limiter: limiter}
	if !limiter.acquire() {
		c.reason = ReasonResourceLimit
		return c
	}
	c.admitted = true
	c.buffer = make([]byte, 0, maxRetainedWindow)
	return c
}

// Feed accepts arbitrary chunk sizes while retaining no more than maxRetainedWindow input bytes.
func (c *Carver) Feed(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.admitted || len(data) == 0 {
		return
	}
	for len(data) > 0 {
		n := len(data)
		if n > maxPatchSize {
			n = maxPatchSize
		}
		oldTotal := c.total
		chunk := data[:n]
		c.appendWindow(chunk)
		c.total += int64(n)
		base := c.total - int64(len(c.buffer))
		first := int(oldTotal-base) - (len(rsaEncryptionOID) - 1)
		if first < 0 {
			first = 0
		}
		for pos := first; pos+len(rsaEncryptionOID) <= len(c.buffer); pos++ {
			key, ok := anchorKey(c.buffer, pos)
			if !ok {
				continue
			}
			c.addPending(anchorCandidate{absolute: base + int64(pos), key: key})
		}
		c.tryPending()
		data = data[n:]
		if c.config != nil && c.config.XORKey == defaultXORKeys[0] && len(data) > 0 {
			c.total += int64(len(data))
			return
		}
	}
}

func (c *Carver) appendWindow(data []byte) {
	if len(data) >= maxRetainedWindow {
		c.buffer = append(c.buffer[:0], data[len(data)-maxRetainedWindow:]...)
		return
	}
	need := len(c.buffer) + len(data) - maxRetainedWindow
	if need > 0 {
		copy(c.buffer, c.buffer[need:])
		c.buffer = c.buffer[:len(c.buffer)-need]
	}
	c.buffer = append(c.buffer, data...)
}

func (c *Carver) addPending(candidate anchorCandidate) {
	for _, old := range c.pending {
		if old.absolute == candidate.absolute && old.key == candidate.key {
			return
		}
	}
	if len(c.pending) >= maxRetainedWindow/len(rsaEncryptionOID) {
		copy(c.pending, c.pending[1:])
		c.pending = c.pending[:len(c.pending)-1]
	}
	c.pending = append(c.pending, candidate)
}

func (c *Carver) tryPending() {
	base := c.total - int64(len(c.buffer))
	kept := c.pending[:0]
	for _, candidate := range c.pending {
		offset := int(candidate.absolute - base)
		if offset < 0 || offset >= len(c.buffer) {
			continue
		}
		if got := carveAtAnchor(c.buffer, offset, candidate.key, c.versions); got != nil {
			c.consider(got)
			continue
		}
		kept = append(kept, candidate)
	}
	c.pending = kept
}

func (c *Carver) consider(candidate *Config) {
	if candidate == nil {
		return
	}
	if c.config == nil || keyPrecedes(candidate, c.config) {
		c.config = candidate
	}
}

func keyPrecedes(a, b *Config) bool {
	rank := func(key byte) int {
		for i, candidate := range defaultXORKeys {
			if key == candidate {
				return i
			}
		}
		return len(defaultXORKeys)
	}
	ra, rb := rank(a.XORKey), rank(b.XORKey)
	if ra != rb {
		return ra < rb
	}
	if ra < len(defaultXORKeys) {
		return false
	}
	if a.fallbackFrequency != b.fallbackFrequency {
		return a.fallbackFrequency > b.fallbackFrequency
	}
	return a.XORKey < b.XORKey
}

func byteFrequency(data []byte, key byte) int {
	count := 0
	for _, b := range data {
		if b == key {
			count++
		}
	}
	return count
}

func fallbackOrder(window []byte) []byte {
	keys := make([]byte, 0, 256-len(defaultXORKeys))
	for i := 0; i < 256; i++ {
		key := byte(i)
		if key == defaultXORKeys[0] || key == defaultXORKeys[1] || key == defaultXORKeys[2] {
			continue
		}
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		fi, fj := byteFrequency(window, keys[i]), byteFrequency(window, keys[j])
		if fi == fj {
			return keys[i] < keys[j]
		}
		return fi > fj
	})
	return keys
}

func anchorKey(data []byte, pos int) (byte, bool) {
	if pos < 0 || pos+len(rsaEncryptionOID) > len(data) {
		return 0, false
	}
	key := data[pos] ^ rsaEncryptionOID[0]
	for i := 1; i < len(rsaEncryptionOID); i++ {
		if data[pos+i]^key != rsaEncryptionOID[i] {
			return 0, false
		}
	}
	return key, true
}

func carveAtAnchor(raw []byte, anchor int, key byte, versions map[uint16]string) *Config {
	decoded := make([]byte, len(raw))
	for i, value := range raw {
		decoded[i] = value ^ key
	}
	first := anchor - maxPatchSize
	if first < 0 {
		first = 0
	}
	for start := first; start < anchor; start++ {
		settings, maxIndex, terminated, complete := parseSettings(decoded, start)
		if !complete || !terminated || len(settings) < 3 {
			continue
		}
		anchorInPubkey := false
		for i, setting := range settings {
			if setting.Index == settingIndexPubKey && bytes.Contains(setting.Raw, rsaEncryptionOID[:]) {
				valueStart := settingsValueOffset(decoded, start, i)
				if anchor >= valueStart && anchor+len(rsaEncryptionOID) <= valueStart+len(setting.Raw) {
					anchorInPubkey = true
				}
			}
		}
		if !anchorInPubkey {
			continue
		}
		patchSize := oldPatchSize
		if maxIndex >= patch1800Boundary {
			patchSize = maxPatchSize
		}
		if start+patchSize > len(decoded) {
			continue
		}
		frequency := byteFrequency(raw, key)
		version := versionFor(maxIndex, versions)
		return &Config{Settings: settings, MaxSettingIndex: maxIndex, Version: version, VersionAnnotation: versionAnnotation(maxIndex, version), PatchSize: patchSize, XORKey: key, fallbackFrequency: frequency}
	}
	return nil
}

func settingsValueOffset(decoded []byte, start, target int) int {
	pos := start
	for i := 0; i < target; i++ {
		if pos+settingHeaderSize > len(decoded) {
			return len(decoded)
		}
		length := int(binary.BigEndian.Uint16(decoded[pos+4 : pos+6]))
		pos += settingHeaderSize + length
	}
	return pos + settingHeaderSize
}

// Result finalizes wrapper checks against total bytes fed and returns a parsed config if present.
func (c *Carver) Result() (*Config, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.config != nil {
		c.releaseLocked()
		return c.config, true
	}
	if !c.admitted {
		return nil, false
	}
	c.tryPending()

	if c.config == nil && c.total <= int64(maxRetainedWindow) {
		if wrapped, invalid := findXorEncoded(bytes.Clone(c.buffer), c.total, c.versions); wrapped != nil {
			c.config = wrapped
		} else if invalid {
			c.badWrapper = true
		}
	}
	if c.config == nil {
		if c.badWrapper {
			c.reason = ReasonInvalidStage
		} else if c.total > int64(maxRetainedWindow) {
			c.reason = ReasonOutOfScope
		} else {
			c.reason = ReasonNoAnchor
		}
		c.releaseLocked()
		return nil, false
	}
	c.releaseLocked()
	return c.config, true
}

func findDecodedConfig(raw []byte, key byte, versions map[uint16]string) *Config {
	decoded := make([]byte, len(raw))
	for i, value := range raw {
		decoded[i] = value ^ key
	}
	for pos := 0; pos+len(rsaEncryptionOID) <= len(decoded); {
		i := bytes.Index(decoded[pos:], rsaEncryptionOID[:])
		if i < 0 {
			return nil
		}
		anchor := pos + i
		if got := carveAtAnchor(raw, anchor, key, versions); got != nil {
			return got
		}
		pos = anchor + 1
	}
	return nil
}

func orderedKeys(window []byte) []byte {
	keys := make([]byte, 0, 256)
	keys = append(keys, defaultXORKeys[:]...)
	keys = append(keys, fallbackOrder(window)...)
	return keys
}

func findXorEncoded(raw []byte, total int64, versions map[uint16]string) (*Config, bool) {
	invalid := false
	limit := wrapperScanLimit
	if len(raw)-wrapperHeaderSize < limit {
		limit = len(raw) - wrapperHeaderSize + 1
	}
	if limit < 0 {
		return nil, false
	}
	for offset := 0; offset < limit; offset++ {
		nonce := raw[offset : offset+wrapperNonceSize]
		sizeBytes := make([]byte, wrapperNonceSize)
		for i := 0; i < wrapperNonceSize; i++ {
			sizeBytes[i] = nonce[i] ^ raw[offset+wrapperNonceSize+i]
		}
		size := int64(binary.LittleEndian.Uint32(sizeBytes))
		if size < wrapperMinimumSize {
			continue
		}
		end := int64(offset+wrapperHeaderSize) + size
		if end > total || total-end > wrapperMaximumSlack || end > int64(len(raw)) {
			invalid = true
			continue
		}
		start := offset + wrapperHeaderSize
		decoded := make([]byte, int(size))
		for i := range decoded {
			prior := nonce[i%wrapperNonceSize]
			if i >= wrapperNonceSize {
				prior = raw[start+i-wrapperNonceSize]
			}
			decoded[i] = raw[start+i] ^ prior
		}
		for _, key := range orderedKeys(decoded) {
			if got := findDecodedConfig(decoded, key, versions); got != nil {
				got.XorEncoded = true
				return got, invalid
			}
		}
	}
	return nil, invalid
}

func (c *Carver) Reason() Reason {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reason
}

func (c *Carver) RetainedBytes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.buffer)
}

func (c *Carver) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.releaseLocked()
	c.closed = true
}

func (c *Carver) releaseLocked() {
	if c.admitted && !c.closed {
		c.limiter.release()
		c.admitted = false
	}
}
