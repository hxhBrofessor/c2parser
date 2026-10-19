//go:build !unix && !windows

package main

import (
	"errors"
	"os"
)

// Fail closed where the platform does not provide the anchored same-directory
// rename used for atomic sidecar publication.
func renameCandidateAt(_ *os.Root, _ *os.File, _, _ string) error {
	return errors.New("atomic anchored candidate sidecar publication is unsupported on this platform")
}
