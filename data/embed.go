// Package data exposes validated, embedded framework-profile metadata.
// Slice 1 intentionally ships no production fingerprint rows.
package data

import _ "embed"

//go:embed framework-fingerprints.yaml
var frameworkFingerprintsYAML []byte
