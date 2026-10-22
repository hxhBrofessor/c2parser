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
	maxPendingAnchors    = 128
	maxCarveWork         = 8192
)

// Default key values and OID bytes are cited in FORMAT.md, "Anchor, patch sizes, and XOR keys".
var (
	defaultXORKeys   = [...]byte{0x69, 0x2e, 0x00}
	rsaEncryptionOID = [...]byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}
)

// Carve reasons are the explicit NOT_CARVED outcomes required by FORMAT.md and the WS-4 order.
type Reason string

const (
	ReasonNone                     Reason = ""
	ReasonNoAnchor                 Reason = "no_anchor"
	ReasonAnchorWithoutValidConfig Reason = "anchor_without_valid_config"
	ReasonWorkBudgetExhausted      Reason = "work_budget_exhausted"
	ReasonInvalidStage             Reason = "invalid_xorencoded_wrapper"
	ReasonResourceLimit            Reason = "resource_limit"
	ReasonOutOfScope               Reason = "out_of_scope_wrapper"
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

type wrapperCandidate struct {
	offset int64
	size   uint32
}

type plainScanner struct {
	buffer    []byte
	total     int64
	pending   []anchorCandidate
	config    *Config
	hadAnchor bool
	workUsed  *int
	exhausted *bool
}

// Carver keeps only a bounded rolling input window and stores parsed results, never payload logs.
type Carver struct {
	mu            sync.Mutex
	options       Options
	versions      map[uint16]string
	limiter       *Limiter
	admitted      bool
	closed        bool
	total         int64
	buffer        []byte // compatibility view of the plain scanner's bounded window
	plain         plainScanner
	derived       plainScanner
	derivedTail   [wrapperNonceSize]byte
	derivedSeen   int
	headerPrefix  []byte
	headerScanned int
	wrappers      []wrapperCandidate
	config        *Config
	reason        Reason
	workUsed      int
	workExhausted bool
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
	c.plain.buffer = make([]byte, 0, maxRetainedWindow)
	c.derived.buffer = make([]byte, 0, maxRetainedWindow)
	c.buffer = c.plain.buffer
	c.plain.workUsed, c.derived.workUsed = &c.workUsed, &c.workUsed
	c.plain.exhausted, c.derived.exhausted = &c.workExhausted, &c.workExhausted
	// Four prefix bytes preserve absolute positions in the derived stream.
	c.derived.feed(make([]byte, wrapperNonceSize), versions, false)
	return c
}

// Feed accepts arbitrary chunk sizes while retaining two bounded decode windows.
func (c *Carver) Feed(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.admitted || len(data) == 0 {
		return
	}
	oldTotal := c.total
	c.scanWrapperHeaders(data, oldTotal)
	for len(data) > 0 {
		n := len(data)
		if n > maxPatchSize {
			n = maxPatchSize
		}
		chunk := data[:n]
		c.feedDerived(chunk)
		c.plain.feed(chunk, c.versions, false)
		c.buffer = c.plain.buffer
		c.total += int64(n)
		data = data[n:]
	}
}

func (c *Carver) feedDerived(data []byte) {
	derived := make([]byte, 0, len(data))
	for _, value := range data {
		if c.derivedSeen >= wrapperNonceSize {
			derived = append(derived, value^c.derivedTail[c.derivedSeen%wrapperNonceSize])
		}
		c.derivedTail[c.derivedSeen%wrapperNonceSize] = value
		c.derivedSeen++
	}
	c.derived.feed(derived, c.versions, false)
}

func (c *Carver) scanWrapperHeaders(data []byte, oldTotal int64) {
	const prefixLimit = wrapperScanLimit + wrapperHeaderSize
	if oldTotal < prefixLimit {
		need := prefixLimit - len(c.headerPrefix)
		if need > len(data) {
			need = len(data)
		}
		if need > 0 {
			c.headerPrefix = append(c.headerPrefix, data[:need]...)
		}
	}
	for c.headerScanned < wrapperScanLimit && c.headerScanned+wrapperHeaderSize <= len(c.headerPrefix) {
		offset := c.headerScanned
		c.headerScanned++
		header := c.headerPrefix[offset : offset+wrapperHeaderSize]
		var sizeBytes [wrapperNonceSize]byte
		for i := range sizeBytes {
			sizeBytes[i] = header[i] ^ header[wrapperNonceSize+i]
		}
		size := binary.LittleEndian.Uint32(sizeBytes[:])
		if size >= wrapperMinimumSize {
			c.wrappers = append(c.wrappers, wrapperCandidate{offset: int64(offset), size: size})
		}
	}
}

func validateWrappedConfig(candidate wrapperCandidate, configStart, configEnd, total int64) (valid, invalid bool) {
	end := candidate.offset + wrapperHeaderSize + int64(candidate.size)
	inside := configStart >= candidate.offset+12 && configEnd <= end && configStart < configEnd
	if inside && end <= total && total-end <= wrapperMaximumSlack {
		return true, false
	}
	return false, true
}

func (s *plainScanner) appendWindow(data []byte) {
	if len(data) >= maxRetainedWindow {
		s.buffer = append(s.buffer[:0], data[len(data)-maxRetainedWindow:]...)
		return
	}
	need := len(s.buffer) + len(data) - maxRetainedWindow
	if need > 0 {
		copy(s.buffer, s.buffer[need:])
		s.buffer = s.buffer[:len(s.buffer)-need]
	}
	s.buffer = append(s.buffer, data...)
}

func (s *plainScanner) feed(data []byte, versions map[uint16]string, final bool) {
	for len(data) > 0 && !*s.exhausted {
		n := len(data)
		if n > maxPatchSize {
			n = maxPatchSize
		}
		oldTotal := s.total
		chunk := data[:n]
		s.appendWindow(chunk)
		s.total += int64(n)
		base := s.total - int64(len(s.buffer))
		first := int(oldTotal-base) - (len(rsaEncryptionOID) - 1)
		if first < 0 {
			first = 0
		}
		for pos := first; pos+len(rsaEncryptionOID) <= len(s.buffer); pos++ {
			key, ok := anchorKey(s.buffer, pos)
			if ok {
				s.hadAnchor = true
				s.addPending(anchorCandidate{absolute: base + int64(pos), key: key})
			}
		}
		s.tryPending(versions, false)
		data = data[n:]
	}
	if final {
		s.tryPending(versions, true)
	}
}

func (s *plainScanner) addPending(candidate anchorCandidate) {
	for _, old := range s.pending {
		if old.absolute == candidate.absolute && old.key == candidate.key {
			return
		}
	}
	if len(s.pending) >= maxPendingAnchors {
		return
	}
	s.pending = append(s.pending, candidate)
}

func (s *plainScanner) tryPending(versions map[uint16]string, final bool) {
	base := s.total - int64(len(s.buffer))
	kept := s.pending[:0]
	for _, candidate := range s.pending {
		if !final && candidate.absolute+maxPatchSize > s.total {
			kept = append(kept, candidate)
			continue
		}
		if *s.exhausted {
			break
		}
		offset := int(candidate.absolute - base)
		if offset < 0 || offset >= len(s.buffer) {
			continue
		}
		first := offset - maxPatchSize
		if first < 0 {
			first = 0
		}
		last := offset + maxPatchSize
		if last > len(s.buffer) {
			last = len(s.buffer)
		}
		local := s.buffer[first:last]
		if got := carveAtAnchor(local, offset-first, candidate.key, versions, s.workUsed, s.exhausted); got != nil {
			got.absoluteStart += base + int64(first)
			if s.config == nil || keyPrecedes(got, s.config) || (got.XORKey == s.config.XORKey && got.absoluteStart < s.config.absoluteStart) {
				s.config = got
			}
		}
	}
	if *s.exhausted {
		s.pending = nil
	} else {
		s.pending = kept
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

func carveAtAnchor(raw []byte, anchor int, key byte, versions map[uint16]string, work *int, exhausted *bool) *Config {
	decoded := make([]byte, len(raw))
	for i, value := range raw {
		decoded[i] = value ^ key
	}
	first := anchor - maxPatchSize
	if first < 0 {
		first = 0
	}
	for start := first; start < anchor; start++ {
		if *work >= maxCarveWork {
			*exhausted = true
			return nil
		}
		(*work)++
		settings, maxIndex, terminated, complete := parseSettings(decoded, start)
		if !complete || !terminated || len(settings) < 3 {
			continue
		}
		anchorInPubkey := false
		for i, setting := range settings {
			if setting.Index == settingIndexPubKey && setting.Type == TypePtr && bytes.Contains(setting.Raw, rsaEncryptionOID[:]) {
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
		return &Config{Settings: settings, MaxSettingIndex: maxIndex, Version: version, VersionAnnotation: versionAnnotation(maxIndex, version), PatchSize: patchSize, XORKey: key, fallbackFrequency: frequency, absoluteStart: int64(start)}
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
	c.plain.tryPending(c.versions, true)
	c.derived.tryPending(c.versions, true)
	c.buffer = c.plain.buffer
	if c.plain.config != nil {
		c.config = c.plain.config
	}
	if c.config == nil && c.derived.config != nil {
		for _, candidate := range c.wrappers {
			configStart := c.derived.config.absoluteStart
			configEnd := configStart + int64(c.derived.config.PatchSize)
			valid, invalid := validateWrappedConfig(candidate, configStart, configEnd, c.total)
			if valid {
				c.config = c.derived.config
				c.config.XorEncoded = true
				break
			}
			if invalid {
				c.reason = ReasonInvalidStage
			}
		}
	}
	if c.config == nil {
		if c.workExhausted {
			c.reason = ReasonWorkBudgetExhausted
		} else if c.reason != ReasonInvalidStage {
			if c.plain.hadAnchor || c.derived.hadAnchor {
				c.reason = ReasonAnchorWithoutValidConfig
			} else {
				c.reason = ReasonNoAnchor
			}
		}
		c.releaseLocked()
		return nil, false
	}
	c.releaseLocked()
	return c.config, true
}

func (c *Carver) Reason() Reason {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reason
}

func (c *Carver) RetainedBytes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.plain.buffer) + len(c.derived.buffer)
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
