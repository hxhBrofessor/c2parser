package csconfig

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Wire type codes and setting identifiers come from FORMAT.md, sections
// "Setting block — reference facts" and "Setting identifiers and reused-index rules".
const (
	TypeNone  uint16 = 0
	TypeShort uint16 = 1
	TypeInt   uint16 = 2
	TypePtr   uint16 = 3

	settingHeaderSize    = 6
	settingIndexPubKey   = 7
	versionReuseBoundary = 74
	patch1800Boundary    = 76
)

// Setting preserves raw bytes, including values whose typed width is unusual.
type Setting struct {
	Index            uint16 `json:"index"`
	Name             string `json:"name"`
	Type             uint16 `json:"type"`
	Raw              []byte `json:"raw"`
	Number           uint64 `json:"number,omitempty"`
	HasNumber        bool   `json:"has_number,omitempty"`
	UnexpectedLength bool   `json:"unexpected_length,omitempty"`
}

// Config contains passive settings extracted from one bounded candidate block.
type Config struct {
	Settings          []Setting `json:"settings"`
	MaxSettingIndex   uint16    `json:"max_setting_index"`
	Version           string    `json:"version"`
	PatchSize         int       `json:"patch_size"`
	XORKey            byte      `json:"xor_key"`
	XorEncoded        bool      `json:"xorencoded"`
	fallbackFrequency int
}

func parseSettings(data []byte, start int) ([]Setting, uint16, bool, bool) {
	if start < 0 || start >= len(data) {
		return nil, 0, false, false
	}
	settings := make([]Setting, 0, 16)
	maxIndex := uint16(0)
	pos := start
	for pos+2 <= len(data) {
		index := binary.BigEndian.Uint16(data[pos : pos+2])
		if index == 0 {
			if len(settings) < 3 {
				return nil, maxIndex, false, true
			}
			for i := range settings {
				settings[i].Name = settingName(settings[i].Index, settings[i].Type, maxIndex)
			}
			return settings, maxIndex, true, true
		}
		if pos+settingHeaderSize > len(data) {
			return nil, maxIndex, false, false
		}
		typ := binary.BigEndian.Uint16(data[pos+2 : pos+4])
		length := int(binary.BigEndian.Uint16(data[pos+4 : pos+6]))
		if typ > TypePtr || length > len(data)-pos-settingHeaderSize {
			return nil, maxIndex, false, false
		}
		valueStart := pos + settingHeaderSize
		valueEnd := valueStart + length
		value := append([]byte(nil), data[valueStart:valueEnd]...)
		setting := Setting{Index: index, Type: typ, Raw: value}
		if typ == TypeShort || typ == TypeInt {
			if length == 2 {
				setting.Number = uint64(binary.BigEndian.Uint16(value))
				setting.HasNumber = true
			} else if length == 4 {
				setting.Number = uint64(binary.BigEndian.Uint32(value))
				setting.HasNumber = true
			} else {
				setting.UnexpectedLength = true
			}
		}
		settings = append(settings, setting)
		if index > maxIndex {
			maxIndex = index
		}
		pos = valueEnd
	}
	return nil, maxIndex, false, false
}

// Numeric cases are setting IDs from FORMAT.md, "Setting identifiers and reused-index rules".
func settingName(index, typ, maxIndex uint16) string {
	switch index {
	case 1:
		return "PROTOCOL"
	case 2:
		return "PORT"
	case 3:
		return "SLEEPTIME"
	case 4:
		return "MAXGET"
	case 5:
		return "JITTER"
	case 6:
		return "MAXDNS"
	case settingIndexPubKey:
		return "PUBKEY"
	case 8:
		return "DOMAINS"
	case 9:
		return "USERAGENT"
	case 10:
		return "SUBMITURI"
	case 11:
		return "C2_RECOVER"
	case 12:
		return "C2_REQUEST"
	case 13:
		return "C2_POSTREQ"
	case 14:
		return "SPAWNTO"
	case 15:
		return "PIPENAME"
	case 16:
		if maxIndex < versionReuseBoundary {
			return "KILLDATE_YEAR"
		}
		return "BOF_ALLOCATOR"
	case 17:
		if typ == TypeShort {
			return "KILLDATE_MONTH"
		}
		return "SYSCALL_METHOD"
	case 19:
		return "DNS_IDLE"
	case 20:
		return "DNS_SLEEP"
	case 26:
		return "C2_VERB_GET"
	case 27:
		return "C2_VERB_POST"
	case 36:
		if typ == TypeShort {
			return "INJECT_OPTIONS"
		}
		return "WATERMARKHASH"
	case 37:
		return "WATERMARK"
	case 48:
		if typ == TypeShort && maxIndex < versionReuseBoundary {
			return "PROCINJ_ALLOWED"
		}
		return "PROCINJ_BOF_REUSE_MEM"
	case 54:
		return "HOST_HEADER"
	case 57:
		return "SMB_FRAME_HEADER"
	case 58:
		return "TCP_FRAME_HEADER"
	case 59:
		return "HEADERS_REMOVE"
	case 74:
		return "MASKED_WATERMARK"
	default:
		return fmt.Sprintf("SETTING_%d", index)
	}
}

func hasOID(value []byte, oid []byte) bool {
	return bytes.Contains(value, oid)
}
