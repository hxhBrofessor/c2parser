package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"c2parser/data"
)

const (
	b34V11aSource        = "425897e8c36005e001e6f6254ede16117194f9d2"
	maxEvidenceJSONBytes = 1 << 20
	maxEvidenceJSONDepth = 64
)

// strictEvidenceValue walks decoder tokens so duplicate object keys are rejected
// at every nesting level; encoding/json's ordinary map decoding would overwrite them.
func strictEvidenceValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxEvidenceJSONDepth {
		return nil, fmt.Errorf("JSON nesting exceeds %d", maxEvidenceJSONDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch tok {
	case json.Delim('{'):
		out := make(map[string]any)
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("object key is not a string")
			}
			if _, exists := out[key]; exists {
				return nil, fmt.Errorf("duplicate JSON key %q", key)
			}
			value, err := strictEvidenceValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = value
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return nil, fmt.Errorf("unterminated JSON object")
		}
		return out, nil
	case json.Delim('['):
		out := make([]any, 0)
		for dec.More() {
			value, err := strictEvidenceValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return nil, fmt.Errorf("unterminated JSON array")
		}
		return out, nil
	case json.Delim('}'), json.Delim(']'):
		return nil, fmt.Errorf("unexpected closing delimiter %v", tok)
	default:
		return tok, nil
	}
}

func readBoundedEvidenceJSON(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maxEvidenceJSONBytes {
		return nil, fmt.Errorf("evidence JSON file type or size outside allowed bounds")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() < 1 || after.Size() > maxEvidenceJSONBytes {
		return nil, fmt.Errorf("evidence JSON changed or exceeded size bound while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxEvidenceJSONBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > maxEvidenceJSONBytes {
		return nil, fmt.Errorf("evidence JSON size outside allowed bounds")
	}
	return raw, nil
}

func parseStrictEvidenceJSON(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > maxEvidenceJSONBytes {
		return nil, fmt.Errorf("JSON size outside 1..%d bytes", maxEvidenceJSONBytes)
	}
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("JSON is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := strictEvidenceValue(dec, 0)
	if err != nil {
		return nil, err
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("JSON root must be an object")
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("trailing JSON document")
		}
		return nil, fmt.Errorf("trailing bytes: %w", err)
	}
	return root, nil
}

func safeTrackedEvidencePath(root, rel string) (string, error) {
	if filepath.IsAbs(rel) || strings.Contains(rel, `\`) || !strings.HasPrefix(rel, "evidence/") {
		return "", fmt.Errorf("unsafe tracked evidence path %q", rel)
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.ToSlash(clean) != rel {
		return "", fmt.Errorf("non-canonical tracked evidence path %q", rel)
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", err
	}
	current := rootReal
	parts := strings.Split(filepath.FromSlash(rel), string(filepath.Separator))
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink in tracked evidence path %q", rel)
		}
		if i < len(parts)-1 && !info.IsDir() {
			return "", fmt.Errorf("non-directory path component in %q", rel)
		}
		if i == len(parts)-1 && !info.Mode().IsRegular() {
			return "", fmt.Errorf("tracked evidence path is not a regular file: %q", rel)
		}
	}
	resolved, err := filepath.EvalSymlinks(current)
	if err != nil {
		return "", err
	}
	relCheck, err := filepath.Rel(rootReal, resolved)
	if err != nil || relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("tracked evidence path escapes repository root")
	}
	return current, nil
}

func normalizeTrackedJSONPaths(root string, listed []string) ([]string, error) {
	set := make(map[string]bool)
	for _, rel := range listed {
		if !strings.HasSuffix(rel, ".json") {
			continue
		}
		if _, err := safeTrackedEvidencePath(root, rel); err != nil {
			return nil, err
		}
		if set[rel] {
			return nil, fmt.Errorf("duplicate tracked path %q", rel)
		}
		set[rel] = true
	}
	out := make([]string, 0, len(set))
	for rel := range set {
		out = append(out, rel)
	}
	sort.Strings(out)
	return out, nil
}

func discoverTrackedEvidenceJSON(root string) ([]string, error) {
	if _, err := os.Lstat(filepath.Join(root, ".git")); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("inspect Git metadata: %w", err)
		}
		// Source export without Git metadata: every present file is in scope.
		return walkEvidenceJSON(root)
	}
	cmd := exec.Command("git", "ls-files", "-z", "--", "evidence")
	cmd.Dir = root
	dataBytes, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files evidence: %w", err)
	}
	listed := strings.Split(strings.TrimSuffix(string(dataBytes), "\x00"), "\x00")
	return normalizeTrackedJSONPaths(root, listed)
}

func walkEvidenceJSON(root string) ([]string, error) {
	var listed []string
	err := filepath.WalkDir(filepath.Join(root, "evidence"), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in evidence tree: %s", p)
		}
		if !d.IsDir() {
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			listed = append(listed, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return normalizeTrackedJSONPaths(root, listed)
}

func object(value any, name string) (map[string]any, error) {
	m, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", name)
	}
	return m, nil
}

func stringField(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func arrayField(m map[string]any, key string) ([]any, error) {
	v, ok := m[key].([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", key)
	}
	return v, nil
}

func evidenceRows(root map[string]any, key string) ([]map[string]any, error) {
	values, err := arrayField(root, key)
	if err != nil {
		return nil, err
	}
	rows := make([]map[string]any, 0, len(values))
	for i, value := range values {
		row, err := object(value, fmt.Sprintf("%s[%d]", key, i))
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func validateD07Crosswalk(framework string, profile []data.Item, debt, source map[string]any) error {
	for name, root := range map[string]map[string]any{"debt": debt, "source map": source} {
		if commit := stringField(root, "source_commit"); commit != "" && commit != b34V11aSource {
			return fmt.Errorf("%s root source commit is not the pinned v11a object", name)
		}
	}
	if framework != "poshc2" && framework != "cobaltstrike" {
		return fmt.Errorf("unregistered crosswalk framework %q", framework)
	}
	if framework == "cobaltstrike" && (stringField(debt, "framework") != framework || stringField(debt, "evidence") != "UNKNOWN" || debt["verify"] != false) {
		return fmt.Errorf("Cobalt debt framework/evidence status mismatch")
	}
	if status := stringField(debt, "external_provenance"); status != "PENDING" {
		return fmt.Errorf("debt external provenance status is not pending")
	}
	if status := stringField(source, "external_provenance"); status != "" && status != "PENDING" {
		return fmt.Errorf("source-map external provenance status is contradictory")
	}
	debtRows, err := evidenceRows(debt, "items")
	if err != nil {
		return err
	}
	sourceRows, err := evidenceRows(source, "ordered_predicates")
	if err != nil {
		return err
	}
	if len(profile) == 0 || len(debtRows) != len(profile) || len(sourceRows) != len(profile) {
		return fmt.Errorf("D-07 crosswalk cardinality mismatch")
	}
	indexRows := func(rows []map[string]any, inheritedCommit string) (map[string]map[string]any, error) {
		indexed := make(map[string]map[string]any, len(rows))
		debts := make(map[string]bool, len(rows))
		for _, row := range rows {
			id, debtID := stringField(row, "id"), stringField(row, "debt_id")
			if id == "" || debtID == "" || indexed[id] != nil || debts[debtID] {
				return nil, fmt.Errorf("duplicate or missing D-07 identity")
			}
			if stringField(row, "source_commit") == "" {
				row["source_commit"] = inheritedCommit
			}
			indexed[id], debts[debtID] = row, true
		}
		return indexed, nil
	}
	debtIndex, err := indexRows(debtRows, stringField(debt, "source_commit"))
	if err != nil {
		return err
	}
	sourceIndex, err := indexRows(sourceRows, stringField(source, "source_commit"))
	if err != nil {
		return err
	}
	profileIDs, profileDebts := make(map[string]bool), make(map[string]bool)
	for _, item := range profile {
		if item.ID == "" || item.DebtID == "" || profileIDs[item.ID] || profileDebts[item.DebtID] {
			return fmt.Errorf("duplicate or missing registered profile identity")
		}
		profileIDs[item.ID], profileDebts[item.DebtID] = true, true
		debtRow, debtOK := debtIndex[item.ID]
		sourceRow, sourceOK := sourceIndex[item.ID]
		if !debtOK || !sourceOK || stringField(debtRow, "debt_id") != item.DebtID || stringField(sourceRow, "debt_id") != item.DebtID {
			return fmt.Errorf("D-07 ID/debt binding mismatch for %s", item.ID)
		}
		commit, path, lines, ok := parseV11aLocator(item.Locator)
		if !ok || commit != b34V11aSource {
			return fmt.Errorf("un-pinned profile source locator for %s", item.ID)
		}
		if provenance := stringField(debtRow, "provenance"); !strings.Contains(strings.ToLower(provenance), "pinned-code carry-forward only") || !strings.Contains(strings.ToLower(provenance), "pending") {
			return fmt.Errorf("D-07 debt provenance status mismatch for %s", item.ID)
		}
		if provenance := stringField(sourceRow, "provenance"); provenance != "" && (!strings.Contains(strings.ToLower(provenance), "pinned-code carry-forward only") || !strings.Contains(strings.ToLower(provenance), "pending")) {
			return fmt.Errorf("D-07 source-map provenance status mismatch for %s", item.ID)
		}
		for _, row := range []map[string]any{debtRow, sourceRow} {
			rowCommit := stringField(row, "source_commit")
			if rowCommit == "" {
				rowCommit = stringField(debt, "source_commit")
			}
			if rowCommit == "" {
				rowCommit = stringField(source, "source_commit")
			}
			if rowCommit != commit || stringField(row, "source_path") != path || stringField(row, "source_lines") != lines {
				return fmt.Errorf("D-07 source pointer mismatch for %s", item.ID)
			}
		}
		if framework == "cobaltstrike" {
			debtMatch, sourceMatch := stringField(debtRow, "match_lines"), stringField(sourceRow, "match_lines")
			if debtMatch != sourceMatch {
				return fmt.Errorf("Cobalt match-line binding mismatch for %s", item.ID)
			}
			if item.ID == "cobaltstrike-http-get-default-uri-cookie" && sourceMatch != "135-138" {
				return fmt.Errorf("C4-1 supplemental source map mismatch")
			}
		}
	}
	return nil
}

func parseV11aLocator(locator string) (commit, path, lines string, ok bool) {
	const prefix = "repo@"
	if !strings.HasPrefix(locator, prefix) {
		return "", "", "", false
	}
	body := strings.TrimPrefix(locator, prefix)
	colon := strings.IndexByte(body, ':')
	if colon != 40 {
		return "", "", "", false
	}
	commit, remainder := body[:colon], body[colon+1:]
	last := strings.LastIndexByte(remainder, ':')
	if last <= 0 || last == len(remainder)-1 {
		return "", "", "", false
	}
	return commit, remainder[:last], remainder[last+1:], true
}

func TestTrackedEvidenceJSONAndPoshCobaltD07Crosswalk(t *testing.T) {
	wd, err := os.Getwd() // go test runs in the package directory: <root>/internal/engine
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	paths, err := discoverTrackedEvidenceJSON(root)
	if err != nil {
		t.Fatal(err)
	}
	wantRequired := []string{
		"evidence/cobaltstrike-debt-register.json",
		"evidence/cobaltstrike-predicate-source-map.json",
		"evidence/certificate-debt-register.json",
		"evidence/certificate-predicate-source-map.json",
		"evidence/poshc2-debt-register.json",
		"evidence/poshc2-predicate-source-map.json",
	}
	for _, want := range wantRequired {
		if !containsString(paths, want) {
			t.Errorf("tracked recursive JSON inventory omitted %s", want)
		}
	}
	if len(paths) < len(wantRequired) {
		t.Fatalf("tracked recursive JSON inventory unexpectedly small: %v", paths)
	}
	parsed := make(map[string]map[string]any, len(paths))
	for _, rel := range paths {
		full, err := safeTrackedEvidencePath(root, rel)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := readBoundedEvidenceJSON(full)
		if err != nil {
			t.Fatal(err)
		}
		value, err := parseStrictEvidenceJSON(raw)
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			continue
		}
		parsed[rel] = value
	}
	profiles, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	registered, err := registeredFrameworkHTTPItems(profiles)
	if err != nil {
		t.Fatal(err)
	}
	for _, fw := range []struct{ id, debtFile, sourceFile string }{
		{"poshc2", "evidence/poshc2-debt-register.json", "evidence/poshc2-predicate-source-map.json"},
		{"cobaltstrike", "evidence/cobaltstrike-debt-register.json", "evidence/cobaltstrike-predicate-source-map.json"},
	} {
		if err := validateD07Crosswalk(fw.id, registered[fw.id+"/http"], parsed[fw.debtFile], parsed[fw.sourceFile]); err != nil {
			t.Errorf("%s D-07 crosswalk: %v", fw.id, err)
		}
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestDiscoverTrackedEvidenceJSONFailsClosedOnBrokenGitMetadata(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "evidence"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "evidence", "sample.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "missing-git-dir"), filepath.Join(root, ".git")); err != nil {
		t.Fatal(err)
	}
	_, err := discoverTrackedEvidenceJSON(root)
	if err == nil || !strings.Contains(err.Error(), "git ls-files evidence") {
		t.Fatalf("broken Git metadata must fail closed instead of using the source-export fallback: %v", err)
	}
}

func TestStrictEvidenceJSONAdversarialFixtures(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
		pass  bool
	}{
		{"object final LF", []byte("{\"ok\":true}\n"), true},
		{"nested duplicate key", []byte("{\"outer\":{\"x\":1,\"x\":2}}"), false},
		{"root duplicate key", []byte("{\"x\":1,\"x\":2}"), false},
		{"concatenated objects", []byte("{} {}"), false},
		{"literal terminal backslash n", []byte("{}\\n"), false},
		{"invalid UTF-8", []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}, false},
		{"truncated", []byte("{\"x\":"), false},
		{"non-object root", []byte("[]"), false},
		{"oversized", append([]byte("{}"), bytes.Repeat([]byte(" "), maxEvidenceJSONBytes)...), false},
		{"whitespace after root", []byte("{\"n\":1} \t\n"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseStrictEvidenceJSON(tc.input)
			if (err == nil) != tc.pass {
				t.Fatalf("pass=%v, got err=%v", tc.pass, err)
			}
		})
	}
}

func TestTrackedEvidenceDiscoveryRecursesAndRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "evidence", "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	nestedPath := filepath.Join(root, "evidence", "nested", "inside.json")
	if err := os.WriteFile(nestedPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := normalizeTrackedJSONPaths(root, []string{"evidence/nested/inside.json", "evidence/readme.md"})
	if err != nil || !reflect.DeepEqual(got, []string{"evidence/nested/inside.json"}) {
		t.Fatalf("nested discovery: %v %v", got, err)
	}
	if raw, err := os.ReadFile(filepath.Join(root, got[0])); err != nil || func() bool { _, e := parseStrictEvidenceJSON(raw); return e != nil }() {
		t.Fatalf("valid nested JSON fixture: %v", err)
	}
	if err := os.WriteFile(nestedPath, []byte("{\"nested\":}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(nestedPath); err != nil {
		t.Fatal(err)
	} else if _, err := parseStrictEvidenceJSON(raw); err == nil {
		t.Fatal("invalid nested JSON fixture passed")
	}
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "evidence", "nested", "escape.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := normalizeTrackedJSONPaths(root, []string{"evidence/nested/escape.json"}); err == nil {
		t.Fatal("symlink target accepted")
	}
}

func cloneJSONMap(t *testing.T, source map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseStrictEvidenceJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestD07CrosswalkRejectsMutatedBindings(t *testing.T) {
	root := filepath.Join("..", "..")
	read := func(name string) map[string]any {
		b, err := readBoundedEvidenceJSON(filepath.Join(root, "evidence", name))
		if err != nil {
			t.Fatal(err)
		}
		m, err := parseStrictEvidenceJSON(b)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	p, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := registeredFrameworkHTTPItems(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, fw := range []struct{ id, debtFile, sourceFile, debtKey string }{
		{"poshc2", "poshc2-debt-register.json", "poshc2-predicate-source-map.json", "items"},
		{"cobaltstrike", "cobaltstrike-debt-register.json", "cobaltstrike-predicate-source-map.json", "items"},
	} {
		t.Run(fw.id, func(t *testing.T) {
			items := reg[fw.id+"/http"]
			debt, source := read(fw.debtFile), read(fw.sourceFile)
			mustReject := func(name string, d, s map[string]any) {
				t.Helper()
				if err := validateD07Crosswalk(fw.id, items, d, s); err == nil {
					t.Errorf("%s mutation accepted", name)
				}
			}
			missing := cloneJSONMap(t, debt)
			rows, _ := evidenceRows(missing, fw.debtKey)
			missing[fw.debtKey] = rows[:len(rows)-1]
			mustReject("missing debt row", missing, source)
			extra := cloneJSONMap(t, debt)
			rows, _ = evidenceRows(extra, fw.debtKey)
			extra[fw.debtKey] = append(rows, rows[0])
			mustReject("extra/duplicate debt row", extra, source)
			wrong := cloneJSONMap(t, source)
			rows, _ = evidenceRows(wrong, "ordered_predicates")
			rows[0]["id"] = "wrong-item"
			mustReject("wrong item binding", debt, wrong)
			unpinned := cloneJSONMap(t, debt)
			rows, _ = evidenceRows(unpinned, fw.debtKey)
			rows[0]["source_commit"] = "main"
			mustReject("unpinned pointer", unpinned, source)
			duplicateDebt := cloneJSONMap(t, debt)
			rows, _ = evidenceRows(duplicateDebt, fw.debtKey)
			rows[1]["debt_id"] = rows[0]["debt_id"]
			mustReject("duplicate debt id", duplicateDebt, source)
		})
	}
}

func TestPendingGroupsCannotEnterProductionRegistry(t *testing.T) {
	for _, framework := range []string{"covenant", "merlin", "poshc2", "cobaltstrike"} {
		t.Run(framework, func(t *testing.T) {
			p, err := data.Load()
			if err != nil {
				t.Fatal(err)
			}
			for i := range p.Frameworks {
				if p.Frameworks[i].ID == framework {
					g := p.Frameworks[i].FieldGroups["http"]
					g.Verify = true
					g.Items = nil
					p.Frameworks[i].FieldGroups["http"] = g
				}
			}
			if result, err := registeredFrameworkHTTPItems(p); err == nil || result != nil {
				t.Fatalf("pending group reached registry: result=%v err=%v", result, err)
			}
		})
	}
}

func TestProductionRegistryRequiresNonemptyGroupsAndImmutableRevisions(t *testing.T) {
	base, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registeredFrameworkHTTPItems(base); err != nil {
		t.Fatalf("production asset rejected: %v", err)
	}
	for _, tc := range []struct{ name, revision string }{
		{"semantic version", "v1.2.3"},
		{"abbreviated object id", "425897e"},
		{"39 digits", strings.Repeat("a", 39)},
		{"41 digits", strings.Repeat("a", 41)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := cloneProfiles(base)
			g := p.Frameworks[0].FieldGroups["http"]
			g.Source.Revision = tc.revision
			p.Frameworks[0].FieldGroups["http"] = g
			if _, err := registeredFrameworkHTTPItems(p); err == nil || !strings.Contains(err.Error(), "PRODUCTION_SOURCE_REVISION_NOT_IMMUTABLE") {
				t.Fatalf("wrong production revision accepted/refusal: %v", err)
			}
		})
	}
	t.Run("sourced revision null", func(t *testing.T) {
		p := cloneProfiles(base)
		g := p.Frameworks[0].FieldGroups["http"]
		g.Source = nil
		p.Frameworks[0].FieldGroups["http"] = g
		if _, err := registeredFrameworkHTTPItems(p); err == nil {
			t.Fatal("null production source accepted")
		}
	})
	t.Run("empty field groups", func(t *testing.T) {
		p := cloneProfiles(base)
		p.Frameworks[0].FieldGroups = map[string]data.FieldGroup{}
		if _, err := registeredFrameworkHTTPItems(p); err == nil || !strings.Contains(err.Error(), "PRODUCTION_EMPTY_FIELD_GROUPS") {
			t.Fatalf("empty production group map: %v", err)
		}
	})
}

func TestCobaltContentTypeHeaderIsExactBound(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "data", "framework-fingerprints.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"post_submit_id", "response_empty_404"} {
		t.Run(kind, func(t *testing.T) {
			text := string(raw)
			start := strings.Index(text, "kind: "+kind)
			if start < 0 {
				t.Fatal("kind missing from production YAML")
			}
			pos := strings.Index(text[start:], "header: content-type")
			if pos < 0 {
				t.Fatal("exact-bound header missing")
			}
			at := start + pos
			mutated := text[:at] + strings.Replace(text[at:], "header: content-type", "header: x-content-type", 1)
			if _, err := data.ParseProfiles([]byte(mutated)); err == nil {
				t.Fatal("alternate content-type header accepted")
			}
		})
	}
}

func TestCobaltCookieHeaderIsConsumedByMatcher(t *testing.T) {
	p, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	item := p.Frameworks[3].FieldGroups["http"].Items[0]
	item.Header = "x-c2p-cookie"
	e := &Engine{cobaltHTTP: []data.Item{item}}
	ch := &httpChannel{}
	msg := &httpMsg{req: true, method: "GET", uri: item.Values[0], hdr: map[string]string{"x-c2p-cookie": strings.Repeat("A", 40)}, frame: 1}
	e.matchCobaltHTTP(ch, msg, item.Values[0], "", "", 1)
	if len(ch.fw["Cobalt Strike"].feats) != 1 {
		t.Fatal("configured Cookie header was not consumed by the matcher")
	}
}
