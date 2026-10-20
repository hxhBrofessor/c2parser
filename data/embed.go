// Package data exposes validated, embedded framework-profile metadata.
package data

import _ "embed"

//go:embed framework-fingerprints.yaml
var frameworkFingerprintsYAML []byte
