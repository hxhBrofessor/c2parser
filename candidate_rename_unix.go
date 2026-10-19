//go:build unix

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// renameCandidateAt uses the already-open destination directory, so a parent
// path rename or symlink swap cannot redirect atomic publication.
func renameCandidateAt(_ *os.Root, dir *os.File, oldName, newName string) error {
	return unix.Renameat(int(dir.Fd()), oldName, int(dir.Fd()), newName)
}
