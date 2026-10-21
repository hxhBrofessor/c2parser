package engine

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"c2parser/data"
	"c2parser/internal/stats"
)

//go:embed testdata/profiles-golden.json
var profilesGolden []byte

type profileEntry struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

func sortedBoolEntries(m map[string]bool) []profileEntry {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]profileEntry, 0, len(keys))
	for _, k := range keys {
		out = append(out, profileEntry{k, m[k]})
	}
	return out
}

func sortedStringEntries(m map[string]string) []profileEntry {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]profileEntry, 0, len(keys))
	for _, k := range keys {
		out = append(out, profileEntry{k, m[k]})
	}
	return out
}

func sortedFloatEntries(m map[int]string) []profileEntry {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	out := make([]profileEntry, 0, len(keys))
	for _, k := range keys {
		out = append(out, profileEntry{fmt.Sprint(k), m[k]})
	}
	return out
}

func profileSignalFixture(reqs, resps []*httpMsg, want string) any {
	ch := &httpChannel{}
	e := &Engine{}
	for _, m := range reqs {
		e.matchFrameworkDefaults(ch, m)
	}
	for _, m := range resps {
		e.matchFrameworkDefaults(ch, m)
	}
	a := &acc{f: &Finding{}, sigs: map[string]stats.Signal{}}
	scoreFrameworkDefaults(a, ch)
	features := ch.fw[want]
	if features == nil {
		return map[string]any{"error": "expected framework features absent", "framework": want}
	}
	featureRows := make([]profileEntry, 0, len(features.feats))
	for k, v := range features.feats {
		featureRows = append(featureRows, profileEntry{k, v})
	}
	sort.Slice(featureRows, func(i, j int) bool { return featureRows[i].Key < featureRows[j].Key })
	sig, ok := a.sigs["default_profile:"+strings.ToLower(strings.ReplaceAll(want, " ", "_"))]
	if !ok {
		return map[string]any{"error": "expected profile signal absent", "features": featureRows}
	}
	return map[string]any{"name": sig.Name, "score": sig.Score, "detail": sig.Detail, "features": featureRows}
}

func profileGoldenDocument() ([]byte, error) {
	profiles, err := data.Load()
	if err != nil {
		return nil, err
	}
	certItems, err := registeredFrameworkCertItems(profiles)
	if err != nil {
		return nil, err
	}
	certSHA, certSerial := map[string]string{}, map[string]string{}
	for _, framework := range []string{"cobaltstrike", "bruteratel"} {
		for _, item := range certItems[framework+"/cert"] {
			switch item.Kind {
			case "cert_der_sha256_exact":
				certSHA[item.Value] = item.Feature
			case "cert_serial_decimal_exact":
				certSerial[item.Value] = item.Feature
			}
		}
	}
	uriCases := []profileEntry{}
	for _, path := range []string{"/WWWW", "/WWWX", "/beacon.php", "/index.html", "/not-a-shape", "/a.js"} {
		uriCases = append(uriCases, profileEntry{path, uriShapeOf(path)})
	}
	sort.Slice(uriCases, func(i, j int) bool { return uriCases[i].Key < uriCases[j].Key })
	magicHex := make([]string, 0, len(knownFrameMagics))
	for _, m := range knownFrameMagics {
		magicHex = append(magicHex, hex.EncodeToString(m))
	}
	sort.Strings(magicHex)

	type signatureRow struct {
		Name         string  `json:"name"`
		Kind         string  `json:"kind"`
		Weight       float64 `json:"weight"`
		ProbeMatches bool    `json:"probe_matches"`
	}
	probes := map[string][]byte{
		"havoc-demon-header": {0, 0, 0, 12, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 1},
		"pe-executable":      {0x4d, 0x5a},
		"elf-executable":     {0x7f, 'E', 'L', 'F'},
		"zip-archive":        {'P', 'K', 3, 4},
		"7z-archive":         {0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c},
		"rar-archive":        {'R', 'a', 'r', '!', 0x1a, 0x07},
	}
	probes["pe-executable"] = make([]byte, 0x44)
	probes["pe-executable"][0], probes["pe-executable"][1] = 'M', 'Z'
	probes["pe-executable"][0x3c] = 0x40
	copy(probes["pe-executable"][0x40:], []byte("PE\x00\x00"))
	sigRows := make([]signatureRow, 0, len(signatures))
	for _, s := range signatures {
		sigRows = append(sigRows, signatureRow{s.Name, s.Kind, s.Weight, s.match(probes[s.Name])})
	}
	sort.Slice(sigRows, func(i, j int) bool { return sigRows[i].Name < sigRows[j].Name })

	profileRows := []profileEntry{
		{"Covenant", profileSignalFixture(
			[]*httpMsg{{req: true, method: "POST", uri: "/en-us/index.html", hdr: map[string]string{"user-agent": covenantUA, "cookie": "SESSIONID=1552332971750"}, head: []byte("i=a19ea23062db990386a3a478cb89d52e&data=payload")}},
			[]*httpMsg{{proto: "HTTP/1.1", status: 200, hdr: map[string]string{"server": "Microsoft-IIS/7.5"}, head: []byte("<title>Hello World!</title>")}}, "Covenant")},
		{"Merlin", profileSignalFixture(
			[]*httpMsg{{req: true, method: "POST", uri: "/", hdr: map[string]string{"content-type": "application/octet-stream; charset=utf-8", "authorization": "Bearer eyJfixture", "user-agent": merlinUA}}}, nil, "Merlin")},
		{"PoshC2", profileSignalFixture(
			[]*httpMsg{{req: true, method: "GET", uri: "/", hdr: map[string]string{"cookie": "SessionID=fixture"}}},
			[]*httpMsg{{proto: "HTTP/1.0", status: 404, hdr: map[string]string{"content-type": "text/html"}, order: []string{"Content-type"}, serverRaw: "Apache ", head: []byte("IIS ASP.NET 2.0.43451 Server <address>Apache (Debian) Server slack-app-id\" content=\"#av33f33\"")}}, "PoshC2")},
		{"Cobalt Strike", profileSignalFixture(
			[]*httpMsg{{req: true, method: "GET", uri: "/pixel.gif", hdr: map[string]string{"cookie": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno="}}, {req: true, method: "POST", uri: "/submit.php?id=123", hdr: map[string]string{"content-type": "application/octet-stream"}}, {req: true, method: "GET", uri: "/WWWW", hdr: map[string]string{}}},
			[]*httpMsg{{status: 404, hdr: map[string]string{"content-type": "text/plain", "content-length": "0"}, bodyLen: 0}}, "Cobalt Strike")},
	}
	sort.Slice(profileRows, func(i, j int) bool { return profileRows[i].Key < profileRows[j].Key })

	doc := map[string]any{
		"http_defaults": map[string]any{
			"covenantUA": covenantUA, "merlinUA": merlinUA, "fwThreshold": fwThreshold,
			"covenantURIs": sortedBoolEntries(covenantURIs), "csDefaultURIs": sortedBoolEntries(csDefaultURIs),
			"b64CookieRe": b64CookieRe.String(), "csSubmitQRe": csSubmitQRe.String(), "csStagerURIRe": csStagerURIRe.String(),
			"framework_fixtures": profileRows,
		},
		"uri_shape":        map[string]any{"uriShapeWeight": uriShapeWeight, "stagerMinBytes": stagerMinBytes, "wordDotMinFrac": wordDotMinFrac, "wordDotMaxURIs": wordDotMaxURIs, "uriShapeMinReqs": uriShapeMinReqs, "wordDotExtRe": wordDotExtRe.String(), "cases": uriCases},
		"frame_magics_hex": magicHex,
		"signatures":       sigRows,
		"certificates":     map[string]any{"knownCertSHA256": sortedStringEntries(certSHA), "knownCertSerial": sortedStringEntries(certSerial), "generatorSpans": sortedFloatEntries(generatorSpans)},
		"csDNSPrefixSet":   sortedBoolEntries(csDNSPrefixSet),
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func TestProfilesGoldenBaseline(t *testing.T) {
	got, err := profileGoldenDocument()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, profilesGolden) {
		t.Fatalf("profile golden mismatch; generated=%s want=%s", fmt.Sprintf("%x", sha256Bytes(got)), fmt.Sprintf("%x", sha256Bytes(profilesGolden)))
	}
}

func sha256Bytes(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
