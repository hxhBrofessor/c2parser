//go:build unix

package main

import "os"

func openCandidateDirectory(path string) (*os.File, error) {
	return os.Open(path)
}
