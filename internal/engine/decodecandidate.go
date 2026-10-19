package engine

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"math/big"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// DecodeCandidate is a syntactically valid alternate interpretation of an
// HTTP carrier token. It is not evidence that the observed token used this
// encoding. Candidate bytes are JSON-encoded as Base64 by encoding/json.
type DecodeCandidate struct {
	ID                 string `json:"id"`
	FlowID             string `json:"flow_id"`
	Frame              int64  `json:"frame"`
	Direction          string `json:"direction"`
	MessageOrdinal     int    `json:"message_ordinal"`
	TokenOrdinal       int    `json:"token_ordinal"`
	Occurrences        int    `json:"occurrences"`
	Carrier            string `json:"carrier"`
	Location           string `json:"location"`
	TokenSHA256        string `json:"token_sha256"`
	TokenLength        int    `json:"token_length"`
	Encoding           string `json:"encoding"`
	DecodedBytes       []byte `json:"decoded_bytes_base64"`
	SyntaxValidity     string `json:"syntax_validity"`
	Identification     string `json:"identification"`
	IdentificationNote string `json:"identification_note"`
}

// DecodeCandidateLimits documents the fixed resource envelope used by
// opt-in candidate generation.
type DecodeCandidateLimits struct {
	PerTokenEncodings       int `json:"per_token_encodings"`
	TokenBytes              int `json:"token_bytes"`
	DecodedBytesPerRecord   int `json:"decoded_bytes_per_record"`
	TokenAttemptsPerCapture int `json:"token_attempts_per_capture"`
	RecordsPerHTTPChannel   int `json:"records_per_http_channel"`
	BytesPerHTTPChannel     int `json:"bytes_per_http_channel"`
	RecordsPerCapture       int `json:"records_per_capture"`
	BytesPerCapture         int `json:"bytes_per_capture"`
}

// DecodeCandidateTruncation counts candidate output omitted by the bounds.
type DecodeCandidateTruncation struct {
	TokenTooLong     int `json:"token_too_long"`
	IncompleteBody   int `json:"incomplete_body"`
	AttemptLimit     int `json:"attempt_limit"`
	RecordLimit      int `json:"record_limit"`
	DecodedByteLimit int `json:"decoded_byte_limit"`
	ChannelRecordCap int `json:"channel_record_cap"`
	ChannelByteCap   int `json:"channel_byte_cap"`
}

// DecodeCandidateReport is a separate, opt-in sidecar schema. It is never
// embedded in engine.Result or the established report JSON.
type DecodeCandidateReport struct {
	SchemaVersion int                       `json:"schema_version"`
	File          string                    `json:"file"`
	Limits        DecodeCandidateLimits     `json:"limits"`
	Truncated     DecodeCandidateTruncation `json:"truncated"`
	Candidates    []DecodeCandidate         `json:"candidates"`
}

const (
	candidateSchemaVersion      = 2 // adds explicit incomplete-body omission accounting
	maxCandidateEncodings       = 2
	maxCandidateTokenBytes      = 512
	maxCandidateDecodedBytes    = 512
	maxCandidateAttemptsCapture = 8192
	maxCandidateRecordsChannel  = 128
	maxCandidateBytesChannel    = 64 << 10
	maxCandidateRecordsCapture  = 4096
	maxCandidateBytesCapture    = 2 << 20
)

var candidateLimits = DecodeCandidateLimits{
	PerTokenEncodings:       maxCandidateEncodings,
	TokenBytes:              maxCandidateTokenBytes,
	DecodedBytesPerRecord:   maxCandidateDecodedBytes,
	TokenAttemptsPerCapture: maxCandidateAttemptsCapture,
	RecordsPerHTTPChannel:   maxCandidateRecordsChannel,
	BytesPerHTTPChannel:     maxCandidateBytesChannel,
	RecordsPerCapture:       maxCandidateRecordsCapture,
	BytesPerCapture:         maxCandidateBytesCapture,
}

const candidateIdentificationNote = "syntactically valid alternate decoding; token content alone does not establish intended encoding"

type candidateValue struct {
	encoding string
	decoded  []byte
}

func candidateValues(token string) []candidateValue {
	if len(token) == 0 || len(token) > maxCandidateTokenBytes {
		return nil
	}
	var out []candidateValue
	if b, ok := strictBase32Candidate(token); ok && len(b) <= maxCandidateDecodedBytes {
		out = append(out, candidateValue{encoding: "base32", decoded: b})
	}
	if b, ok := strictBase58Candidate(token); ok && len(b) <= maxCandidateDecodedBytes {
		out = append(out, candidateValue{encoding: "base58", decoded: b})
	}
	return out
}

func strictBase32Candidate(s string) ([]byte, bool) {
	if s == "" {
		return nil, false
	}
	encodings := []*base32.Encoding{
		base32.StdEncoding,
		base32.StdEncoding.WithPadding(base32.NoPadding),
	}
	for _, enc := range encodings {
		b, err := enc.DecodeString(s)
		if err == nil && enc.EncodeToString(b) == s {
			return b, true
		}
		// Accept canonical all-lowercase RFC 4648 spellings as a separate
		// syntax variant; mixed-case and noncanonical spellings remain invalid.
		upper := strings.ToUpper(s)
		b, err = enc.DecodeString(upper)
		if err == nil && strings.ToLower(enc.EncodeToString(b)) == s {
			return b, true
		}
	}
	return nil, false
}

const bitcoinBase58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var bitcoinBase58Index = func() [256]int16 {
	var out [256]int16
	for i := range out {
		out[i] = -1
	}
	for i := range bitcoinBase58Alphabet {
		out[bitcoinBase58Alphabet[i]] = int16(i)
	}
	return out
}()

func strictBase58Candidate(s string) ([]byte, bool) {
	if len(s) == 0 || len(s) > maxCandidateTokenBytes {
		return nil, false
	}
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	value := new(big.Int)
	base := big.NewInt(58)
	digit := new(big.Int)
	for i := 0; i < len(s); i++ {
		v := bitcoinBase58Index[s[i]]
		if v < 0 {
			return nil, false
		}
		value.Mul(value, base)
		digit.SetInt64(int64(v))
		value.Add(value, digit)
	}
	mag := value.Bytes()
	out := make([]byte, zeros+len(mag))
	copy(out[zeros:], mag)
	if len(out) > maxCandidateDecodedBytes {
		return nil, false
	}
	return out, true
}

func candidateTokenInput(m *httpMsg, token string) string {
	if m.req {
		if unescaped, err := url.QueryUnescape(token); err == nil {
			return unescaped
		}
	}
	return token
}

func candidateFlowID(k httpChanKey) string {
	value := strings.Join([]string{k.client.String(), k.server.String(),
		strconv.Itoa(int(k.port)), strings.ToLower(k.host)}, "\x00")
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func candidateID(flowID string, frame int64, direction string, messageOrdinal, tokenOrdinal int, location, tokenHash, encoding string) string {
	parts := []string{flowID, big.NewInt(frame).String(), direction,
		big.NewInt(int64(messageOrdinal)).String(), big.NewInt(int64(tokenOrdinal)).String(),
		location, tokenHash, encoding}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func sortDecodeCandidates(candidates []DecodeCandidate) {
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.FlowID != b.FlowID {
			return a.FlowID < b.FlowID
		}
		if a.Frame != b.Frame {
			return a.Frame < b.Frame
		}
		if a.Direction != b.Direction {
			return a.Direction < b.Direction
		}
		if a.MessageOrdinal != b.MessageOrdinal {
			return a.MessageOrdinal < b.MessageOrdinal
		}
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		if a.TokenOrdinal != b.TokenOrdinal {
			return a.TokenOrdinal < b.TokenOrdinal
		}
		if a.TokenSHA256 != b.TokenSHA256 {
			return a.TokenSHA256 < b.TokenSHA256
		}
		return a.Encoding < b.Encoding
	})
}

type candidateCollector struct {
	report   DecodeCandidateReport
	attempts int
	bytes    int
	seen     map[string]struct{}
}

func newCandidateCollector() *candidateCollector {
	return &candidateCollector{
		report: DecodeCandidateReport{SchemaVersion: candidateSchemaVersion, Limits: candidateLimits, Candidates: []DecodeCandidate{}},
		seen:   make(map[string]struct{}),
	}
}

func (e *Engine) collectCandidates(ch *httpChannel, m *httpMsg, tokens []token) {
	collector := e.candidateCollector
	if collector == nil || len(tokens) == 0 {
		return
	}
	if collector.attempts >= maxCandidateAttemptsCapture {
		collector.report.Truncated.AttemptLimit += len(tokens)
		return
	}
	ordered := append([]token(nil), tokens...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].loc != ordered[j].loc {
			return ordered[i].loc < ordered[j].loc
		}
		return ordered[i].val < ordered[j].val
	})
	type tokenOccurrence struct {
		token token
		count int
	}
	unique := make([]tokenOccurrence, 0, len(ordered))
	for _, t := range ordered {
		if n := len(unique); n > 0 && unique[n-1].token.loc == t.loc && unique[n-1].token.val == t.val {
			unique[n-1].count++
			continue
		}
		unique = append(unique, tokenOccurrence{token: t, count: 1})
	}
	flowID := candidateFlowID(ch.key)
	direction, messageOrdinal := "request", ch.requests
	if !m.req {
		direction, messageOrdinal = "response", ch.responses
	}
	for ordinal, occurrence := range unique {
		if collector.attempts >= maxCandidateAttemptsCapture {
			collector.report.Truncated.AttemptLimit += len(unique) - ordinal
			return
		}
		t := occurrence.token
		if len(t.val) == 0 {
			continue
		}
		collector.attempts++
		if len(t.val) > maxCandidateTokenBytes {
			collector.report.Truncated.TokenTooLong++
			continue
		}
		// Response-body tokens are drawn from a fixed-size head sample. A
		// candidate is exact only when the parser observed the complete body
		// and the whole body fits in that sample. Do not decode a retained
		// prefix: Base58 prefixes do not preserve decoded-byte prefixes.
		if t.loc == "resp:body" && (m.truncated || m.bodyLen != int64(len(m.head))) {
			collector.report.Truncated.IncompleteBody++
			continue
		}
		input := candidateTokenInput(m, t.val)
		if len(input) > maxCandidateTokenBytes {
			collector.report.Truncated.TokenTooLong++
			continue
		}
		values := candidateValues(input)
		for _, value := range values {
			tokenSum := sha256.Sum256([]byte(t.val))
			tokenHash := hex.EncodeToString(tokenSum[:])
			id := candidateID(flowID, m.frame, direction, messageOrdinal, ordinal, t.loc, tokenHash, value.encoding)
			if _, duplicate := collector.seen[id]; duplicate {
				continue
			}
			if len(collector.report.Candidates) >= maxCandidateRecordsCapture {
				collector.report.Truncated.RecordLimit++
				continue
			}
			if collector.bytes+len(value.decoded) > maxCandidateBytesCapture {
				collector.report.Truncated.DecodedByteLimit++
				continue
			}
			if ch.candidateRecords >= maxCandidateRecordsChannel {
				collector.report.Truncated.ChannelRecordCap++
				continue
			}
			if ch.candidateBytes+len(value.decoded) > maxCandidateBytesChannel {
				collector.report.Truncated.ChannelByteCap++
				continue
			}
			collector.seen[id] = struct{}{}
			collector.bytes += len(value.decoded)
			ch.candidateRecords++
			ch.candidateBytes += len(value.decoded)
			collector.report.Candidates = append(collector.report.Candidates, DecodeCandidate{
				ID: id, FlowID: flowID, Frame: m.frame, Direction: direction,
				MessageOrdinal: messageOrdinal, TokenOrdinal: ordinal, Carrier: "http", Location: t.loc,
				Occurrences: occurrence.count,
				TokenSHA256: tokenHash, TokenLength: len(t.val), Encoding: value.encoding,
				DecodedBytes: append([]byte(nil), value.decoded...), SyntaxValidity: "valid",
				Identification: "unconfirmed", IdentificationNote: candidateIdentificationNote,
			})
		}
	}
}
