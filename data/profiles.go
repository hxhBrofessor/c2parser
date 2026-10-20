package data

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

const v11aSourceCommit = "425897e8c36005e001e6f6254ede16117194f9d2"

var (
	frameworkIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)
	revisionPattern    = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64}|v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)$`)
	locatorLinePattern = regexp.MustCompile(`^[1-9][0-9]*(?:-[1-9][0-9]*)?$`)
	locatorSymbol      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Evidence identifies the basis for a field group's metadata.
type Evidence string

const (
	EvidenceSourceConfirmed   Evidence = "SOURCE-CONFIRMED"
	EvidenceCaptureObserved   Evidence = "CAPTURE-OBSERVED"
	EvidenceSyntheticModeled  Evidence = "SYNTHETIC-MODELED"
	EvidenceUnknown           Evidence = "UNKNOWN"
	EvidenceBlockedMissingSrc Evidence = "BLOCKED_MISSING_SOURCE"
)

// Profiles is the validated root document.
type Profiles struct {
	SchemaVersion int         `yaml:"schema_version"`
	Frameworks    []Framework `yaml:"frameworks"`
}

// Framework contains only explicitly represented field groups.
type Framework struct {
	ID          string                `yaml:"id"`
	Aliases     []string              `yaml:"aliases,omitempty"`
	FieldGroups map[string]FieldGroup `yaml:"field_groups"`
}

// FieldGroup records evidence and pending-verification status for one group.
type FieldGroup struct {
	Evidence Evidence `yaml:"evidence"`
	// Verify=true means pending verification and not eligible for scoring.
	// Verify=false means potentially consumable, not externally verified.
	Verify bool     `yaml:"verify"`
	Source *Source  `yaml:"source"`
	Items  []string `yaml:"items"`
	Reason string   `yaml:"reason,omitempty"`
}

// Source identifies a pinned provenance record. Slice 1 metadata is not
// consumed by detectors and does not itself assert external verification.
type Source struct {
	ID       string `yaml:"id"`
	Citation string `yaml:"citation"`
	Revision string `yaml:"revision"`
	Locator  string `yaml:"locator,omitempty"`
	Accessed string `yaml:"accessed,omitempty"`
}

type profilesWire struct {
	SchemaVersion *int             `yaml:"schema_version"`
	Frameworks    *[]frameworkWire `yaml:"frameworks"`
}
type frameworkWire struct {
	ID          *string                    `yaml:"id"`
	Aliases     *[]string                  `yaml:"aliases,omitempty"`
	FieldGroups *map[string]fieldGroupWire `yaml:"field_groups"`
}
type fieldGroupWire struct {
	Evidence *Evidence `yaml:"evidence"`
	Verify   *bool     `yaml:"verify"`
	Source   *Source   `yaml:"source"`
	Items    *[]string `yaml:"items"`
	Reason   *string   `yaml:"reason,omitempty"`
}

// Load parses and validates the embedded production asset. Each call returns a
// fresh value, so callers cannot mutate shared package state.
func Load() (Profiles, error) { return ParseProfiles(frameworkFingerprintsYAML) }

// ParseProfiles parses one strict profile document and returns a fresh,
// validated value. It rejects aliases, anchors, custom tags, duplicate and
// unknown keys, and nonempty items under the Slice 1 contract.
func ParseProfiles(src []byte) (Profiles, error) {
	var zero Profiles
	file, err := parser.ParseBytes(src, 0)
	if err != nil {
		return zero, fmt.Errorf("profiles YAML: %w", err)
	}
	if len(file.Docs) != 1 || file.Docs[0].Body == nil {
		return zero, fmt.Errorf("profiles YAML: expected exactly one document")
	}
	if err := rejectYAMLFeatures(file.Docs[0].Body); err != nil {
		return zero, err
	}
	if err := requireKeys(file.Docs[0].Body); err != nil {
		return zero, err
	}

	var wire profilesWire
	if err := yaml.UnmarshalWithOptions(src, &wire, yaml.Strict()); err != nil {
		return zero, fmt.Errorf("profiles schema: %w", err)
	}
	if wire.SchemaVersion == nil {
		return zero, fmt.Errorf("schema_version: required")
	}
	if *wire.SchemaVersion != 1 {
		return zero, fmt.Errorf("schema_version: unsupported value %d", *wire.SchemaVersion)
	}
	if wire.Frameworks == nil {
		return zero, fmt.Errorf("frameworks: required sequence")
	}

	out := Profiles{SchemaVersion: *wire.SchemaVersion, Frameworks: make([]Framework, 0, len(*wire.Frameworks))}
	ids := make(map[string]struct{}, len(*wire.Frameworks))
	aliases := make(map[string]string)
	for i, fw := range *wire.Frameworks {
		prefix := fmt.Sprintf("frameworks[%d]", i)
		if fw.ID == nil || strings.TrimSpace(*fw.ID) == "" {
			return zero, fmt.Errorf("%s.id: required nonempty string", prefix)
		}
		if !frameworkIDPattern.MatchString(*fw.ID) {
			return zero, fmt.Errorf("%s.id: must be canonical lowercase snake_case", prefix)
		}
		if _, ok := ids[*fw.ID]; ok {
			return zero, fmt.Errorf("%s.id: duplicate framework ID %q", prefix, *fw.ID)
		}
		ids[*fw.ID] = struct{}{}
		if fw.FieldGroups == nil {
			return zero, fmt.Errorf("%s.field_groups: required mapping", prefix)
		}
		newFW := Framework{ID: *fw.ID, FieldGroups: make(map[string]FieldGroup, len(*fw.FieldGroups))}
		if fw.Aliases != nil {
			newFW.Aliases = append([]string(nil), (*fw.Aliases)...)
		}
		for _, alias := range newFW.Aliases {
			if strings.TrimSpace(alias) == "" {
				return zero, fmt.Errorf("%s.aliases: values must be nonempty strings", prefix)
			}
			if _, ok := ids[alias]; ok {
				return zero, fmt.Errorf("%s.aliases: alias collides with framework ID %q", prefix, alias)
			}
			if prior, ok := aliases[alias]; ok {
				return zero, fmt.Errorf("%s.aliases: duplicate alias %q (already used by %q)", prefix, alias, prior)
			}
			aliases[alias] = newFW.ID
		}
		for group, g := range *fw.FieldGroups {
			if !allowedGroup(group) {
				return zero, fmt.Errorf("%s.field_groups.%s: unknown field group", prefix, group)
			}
			groupPath := prefix + ".field_groups." + group
			if g.Evidence == nil {
				return zero, fmt.Errorf("%s.evidence: required", groupPath)
			}
			if g.Verify == nil {
				return zero, fmt.Errorf("%s.verify: required boolean", groupPath)
			}
			if g.Items == nil {
				return zero, fmt.Errorf("%s.items: required sequence", groupPath)
			}
			if len(*g.Items) != 0 {
				return zero, fmt.Errorf("%s.items: Slice 1 requires items: []", groupPath)
			}
			if g.Reason != nil && strings.TrimSpace(*g.Reason) == "" {
				return zero, fmt.Errorf("%s.reason: must be nonempty when present", groupPath)
			}
			value := FieldGroup{Evidence: *g.Evidence, Verify: *g.Verify, Items: []string{}}
			if g.Reason != nil {
				value.Reason = *g.Reason
			}
			if g.Source != nil {
				copySource := *g.Source
				value.Source = &copySource
			}
			if err := validateGroup(groupPath, value); err != nil {
				return zero, err
			}
			newFW.FieldGroups[group] = value
		}
		for alias := range aliases {
			if alias == newFW.ID {
				return zero, fmt.Errorf("%s.id: collides with existing alias %q", prefix, alias)
			}
		}
		out.Frameworks = append(out.Frameworks, newFW)
	}
	return out, nil
}

func requireKeys(root ast.Node) error {
	mapping, ok := root.(*ast.MappingNode)
	if !ok {
		return fmt.Errorf("document: expected mapping")
	}
	if err := hasKeys(mapping, "schema_version", "frameworks"); err != nil {
		return fmt.Errorf("document: %w", err)
	}
	frameworksNode := mapValue(mapping, "frameworks")
	seq, ok := frameworksNode.(*ast.SequenceNode)
	if !ok {
		return fmt.Errorf("frameworks: expected sequence")
	}
	for i, item := range seq.Values {
		fw, ok := item.(*ast.MappingNode)
		if !ok {
			return fmt.Errorf("frameworks[%d]: expected mapping", i)
		}
		if err := hasKeys(fw, "id", "field_groups"); err != nil {
			return fmt.Errorf("frameworks[%d]: %w", i, err)
		}
		if aliases := mapValue(fw, "aliases"); aliases != nil {
			if _, ok := aliases.(*ast.SequenceNode); !ok {
				return fmt.Errorf("frameworks[%d].aliases: expected sequence when present", i)
			}
		}
		groups, ok := mapValue(fw, "field_groups").(*ast.MappingNode)
		if !ok {
			return fmt.Errorf("frameworks[%d].field_groups: expected mapping", i)
		}
		for _, entry := range groups.Values {
			key, ok := entry.Key.(ast.ScalarNode)
			if !ok {
				return fmt.Errorf("frameworks[%d].field_groups: keys must be strings", i)
			}
			name, ok := key.GetValue().(string)
			if !ok {
				return fmt.Errorf("frameworks[%d].field_groups: keys must be strings", i)
			}
			g, ok := entry.Value.(*ast.MappingNode)
			if !ok {
				return fmt.Errorf("frameworks[%d].field_groups.%s: expected mapping", i, name)
			}
			if err := hasKeys(g, "evidence", "verify", "source", "items"); err != nil {
				return fmt.Errorf("frameworks[%d].field_groups.%s: %w", i, name, err)
			}
			if reason := mapValue(g, "reason"); reason != nil {
				if _, ok := reason.(*ast.StringNode); !ok {
					return fmt.Errorf("frameworks[%d].field_groups.%s.reason: expected string when present", i, name)
				}
			}
			if source, ok := mapValue(g, "source").(*ast.MappingNode); ok {
				for _, optional := range []string{"locator", "accessed"} {
					if value := mapValue(source, optional); value != nil {
						if _, ok := value.(*ast.StringNode); !ok {
							return fmt.Errorf("frameworks[%d].field_groups.%s.source.%s: expected string when present", i, name, optional)
						}
					}
				}
			}
		}
	}
	return nil
}

func hasKeys(mapping *ast.MappingNode, names ...string) error {
	for _, name := range names {
		if mapValue(mapping, name) == nil {
			return fmt.Errorf("%s: required key missing", name)
		}
	}
	return nil
}

func mapValue(mapping *ast.MappingNode, key string) ast.Node {
	for _, entry := range mapping.Values {
		if scalar, ok := entry.Key.(ast.ScalarNode); ok {
			if value, ok := scalar.GetValue().(string); ok && value == key {
				return entry.Value
			}
		}
	}
	return nil
}

func validateGroup(path string, group FieldGroup) error {
	switch group.Evidence {
	case EvidenceSourceConfirmed, EvidenceCaptureObserved, EvidenceSyntheticModeled:
		if group.Source == nil {
			return fmt.Errorf("%s.source: required for %s", path, group.Evidence)
		}
		return validateSource(path+".source", *group.Source)
	case EvidenceUnknown, EvidenceBlockedMissingSrc:
		if strings.TrimSpace(group.Reason) == "" {
			return fmt.Errorf("%s.reason: required for unresolved %s evidence", path, group.Evidence)
		}
		if group.Source == nil {
			if !group.Verify {
				return fmt.Errorf("%s.verify: null-source %s requires verify: true", path, group.Evidence)
			}
			return nil
		}
		if group.Evidence == EvidenceUnknown && !group.Verify {
			return validateD07(path, *group.Source, group.Reason)
		}
		if !group.Verify {
			return fmt.Errorf("%s.verify: BLOCKED_MISSING_SOURCE requires verify: true", path)
		}
		return validateSource(path+".source", *group.Source)
	default:
		return fmt.Errorf("%s.evidence: unsupported value %q", path, group.Evidence)
	}
}

func validateSource(path string, source Source) error {
	if strings.TrimSpace(source.ID) == "" || source.ID != strings.TrimSpace(source.ID) || strings.TrimSpace(source.Citation) == "" || source.Citation != strings.TrimSpace(source.Citation) {
		return fmt.Errorf("%s: id and citation must be nonempty, trimmed strings", path)
	}
	if !revisionPattern.MatchString(source.Revision) {
		return fmt.Errorf("%s.revision: expected a full lowercase object ID or pinned semantic version", path)
	}
	if source.Locator != "" && strings.TrimSpace(source.Locator) == "" {
		return fmt.Errorf("%s.locator: must be nonempty when present", path)
	}
	if source.Accessed != "" && strings.TrimSpace(source.Accessed) == "" {
		return fmt.Errorf("%s.accessed: must be nonempty when present", path)
	}
	return nil
}

func validateD07(path string, source Source, reason string) error {
	if err := validateSource(path+".source", source); err != nil {
		return err
	}
	if source.Revision != v11aSourceCommit {
		return fmt.Errorf("%s.source.revision: D-07 requires pinned v11a commit %s", path, v11aSourceCommit)
	}
	prefix := "repo@" + v11aSourceCommit + ":"
	if !strings.HasPrefix(source.Locator, prefix) {
		return fmt.Errorf("%s.source.locator: D-07 requires immutable v11a repository pointer", path)
	}
	remainder := strings.TrimPrefix(source.Locator, prefix)
	colon := strings.LastIndexByte(remainder, ':')
	if colon <= 0 || colon == len(remainder)-1 {
		return fmt.Errorf("%s.source.locator: expected commit:repo-relative-path:lines-or-symbol", path)
	}
	repoPath, ref := remainder[:colon], remainder[colon+1:]
	if strings.HasPrefix(repoPath, "/") || strings.Contains(repoPath, "\\") {
		return fmt.Errorf("%s.source.locator: path must be repository-relative", path)
	}
	for _, part := range strings.Split(repoPath, "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("%s.source.locator: invalid repository-relative path", path)
		}
	}
	if !locatorLinePattern.MatchString(ref) && !locatorSymbol.MatchString(ref) {
		return fmt.Errorf("%s.source.locator: expected bounded line range or symbol", path)
	}
	lower := strings.ToLower(reason)
	if strings.TrimSpace(reason) == "" || !(strings.Contains(lower, "external provenance is pending") || strings.Contains(lower, "external provenance pending")) {
		return fmt.Errorf("%s.reason: D-07 must explicitly say external provenance is pending", path)
	}
	return nil
}

func allowedGroup(group string) bool {
	switch group {
	case "http", "cert", "dns", "blob", "transport", "version_map":
		return true
	default:
		return false
	}
}

func rejectYAMLFeatures(node ast.Node) error {
	switch n := node.(type) {
	case *ast.AnchorNode:
		return fmt.Errorf("profiles YAML: anchors are not permitted")
	case *ast.AliasNode:
		return fmt.Errorf("profiles YAML: aliases are not permitted")
	case *ast.TagNode:
		return fmt.Errorf("profiles YAML: custom tags are not permitted")
	case *ast.DocumentNode:
		return rejectYAMLFeatures(n.Body)
	case *ast.MappingNode:
		for _, entry := range n.Values {
			if err := rejectYAMLFeatures(entry); err != nil {
				return err
			}
		}
	case *ast.MappingValueNode:
		if err := rejectYAMLFeatures(entryKey(n)); err != nil {
			return err
		}
		return rejectYAMLFeatures(n.Value)
	case *ast.MappingKeyNode:
		return rejectYAMLFeatures(n.Value)
	case *ast.SequenceNode:
		for _, child := range n.Values {
			if err := rejectYAMLFeatures(child); err != nil {
				return err
			}
		}
	case *ast.SequenceEntryNode:
		return rejectYAMLFeatures(n.Value)
	}
	return nil
}

func entryKey(node *ast.MappingValueNode) ast.Node { return node.Key }
