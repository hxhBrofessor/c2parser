package csconfig

import (
	"embed"
	"encoding/json"
	"fmt"
	"sync"
)

// The map values and index keys are cited in FORMAT.md, "Setting identifiers and reused-index rules".
//
//go:embed version_map.json
var versionMapFile embed.FS

var (
	versionMapOnce sync.Once
	versionMapData map[uint16]string
)

func embeddedVersionMap() map[uint16]string {
	versionMapOnce.Do(func() {
		data, err := versionMapFile.ReadFile("version_map.json")
		if err != nil {
			panic(err)
		}
		versionMapData = make(map[uint16]string)
		if err := json.Unmarshal(data, &versionMapData); err != nil {
			panic(err)
		}
	})
	return cloneVersionMap(versionMapData)
}

func cloneVersionMap(in map[uint16]string) map[uint16]string {
	out := make(map[uint16]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func versionFor(index uint16, versions map[uint16]string) string {
	if v, ok := versions[index]; ok {
		return v
	}
	return "unknown"
}

func versionAnnotation(index uint16, value string) string {
	if value == "unknown" {
		return "unknown"
	}
	return fmt.Sprintf("max setting index %d (%s per dissect.cobaltstrike v1.3.0)", index, value)
}
