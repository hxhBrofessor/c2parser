package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"c2parser/internal/engine"
	"c2parser/internal/report"
)

// candidateDestination anchors publication to an already-open directory.
// Root-relative operations continue to refer to that directory if its path is
// renamed, avoiding a parent-path swap between validation and publication.
type candidateDestination struct {
	root *os.Root
	dir  *os.File
	name string
}

const maxProtectedCandidateInputFiles = 100_000

func (d *candidateDestination) close() {
	_ = d.root.Close()
	_ = d.dir.Close()
}

func candidateProtectedFiles(paths []string, streams ...*os.File) ([]os.FileInfo, error) {
	var protected []os.FileInfo
	for _, path := range paths {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("classify protected input %q: %w", path, err)
		}
		protected = append(protected, info)
		if !info.IsDir() {
			continue
		}
		count := 0
		err = filepath.WalkDir(path, func(current string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			count++
			if count > maxProtectedCandidateInputFiles {
				return fmt.Errorf("protected input directory exceeds %d entries", maxProtectedCandidateInputFiles)
			}
			if entry.IsDir() {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				// Record a regular symlink target as protected, but never walk a
				// linked directory tree.
				if target, err := os.Stat(current); err == nil && target.Mode().IsRegular() {
					protected = append(protected, target)
				}
				return nil
			}
			item, err := entry.Info()
			if err != nil {
				return err
			}
			if item.Mode().IsRegular() {
				fileInfo, err := os.Stat(current)
				if err != nil {
					return err
				}
				protected = append(protected, fileInfo)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("inventory protected input directory %q: %w", path, err)
		}
	}
	for _, stream := range streams {
		if stream == nil {
			continue
		}
		info, err := stream.Stat()
		if err != nil {
			return nil, fmt.Errorf("classify protected output stream: %w", err)
		}
		protected = append(protected, info)
	}
	return protected, nil
}

func openCandidateDestination(path string, protected []os.FileInfo) (*candidateDestination, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("empty candidate JSON path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve candidate JSON path: %w", err)
	}
	parent := filepath.Dir(abs)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return nil, fmt.Errorf("resolve candidate JSON directory: %w", err)
	}
	root, err := os.OpenRoot(resolvedParent)
	if err != nil {
		return nil, fmt.Errorf("open candidate JSON directory: %w", err)
	}
	dir, err := openCandidateDirectory(resolvedParent)
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("open candidate JSON directory handle: %w", err)
	}
	rootInfo, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		_ = dir.Close()
		return nil, fmt.Errorf("stat candidate JSON root: %w", err)
	}
	dirInfo, err := dir.Stat()
	if err != nil || !os.SameFile(rootInfo, dirInfo) {
		_ = root.Close()
		_ = dir.Close()
		if err != nil {
			return nil, fmt.Errorf("stat candidate JSON directory handle: %w", err)
		}
		return nil, errors.New("candidate JSON directory changed during validation")
	}
	dest := &candidateDestination{root: root, dir: dir, name: filepath.Base(abs)}
	if dest.name == "." || dest.name == string(filepath.Separator) || dest.name == ".." {
		dest.close()
		return nil, errors.New("candidate JSON destination must name a file")
	}
	if err := dest.check(protected); err != nil {
		dest.close()
		return nil, err
	}
	return dest, nil
}

// check fails closed for aliases, symlinks, directories and special files.
// A final rename replaces a directory entry atomically; it never opens or
// truncates the destination inode, so a racing hard-link substitution cannot
// overwrite the protected file's contents.
func (d *candidateDestination) check(protected []os.FileInfo) error {
	info, err := d.root.Lstat(d.name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect candidate JSON destination: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("candidate JSON destination must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return errors.New("candidate JSON destination must be a regular file")
	}
	actual, err := d.root.Stat(d.name)
	if err != nil {
		return fmt.Errorf("stat candidate JSON destination: %w", err)
	}
	for _, p := range protected {
		if p == nil {
			return errors.New("cannot classify protected file")
		}
		if os.SameFile(actual, p) {
			return errors.New("candidate JSON destination aliases a protected input or output")
		}
	}
	return nil
}

func writeCandidateSidecar(path string, protected []os.FileInfo, reports []engine.DecodeCandidateReport) error {
	return publishCandidateSidecar(path, protected, func(w io.Writer) error {
		return report.CandidateJSON(w, reports)
	}, nil)
}

// publishCandidateSidecar is split from serialization so failures can be
// tested before publication. The optional hook is only used by race tests to
// replace the destination after validation and before rename.
func publishCandidateSidecar(path string, protected []os.FileInfo, encode func(io.Writer) error, beforeRename func(*os.Root, string) error) (retErr error) {
	dest, err := openCandidateDestination(path, protected)
	if err != nil {
		return err
	}
	defer dest.close()

	var tempName string
	var f *os.File
	for attempt := 0; attempt < 16; attempt++ {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return fmt.Errorf("create candidate JSON temporary name: %w", err)
		}
		tempName = ".c2parser-candidates-" + hex.EncodeToString(nonce[:]) + ".tmp"
		f, err = dest.root.OpenFile(tempName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create candidate JSON temporary file: %w", err)
		}
	}
	if f == nil {
		return errors.New("could not reserve unique candidate JSON temporary file")
	}
	defer func() {
		if tempName != "" {
			if err := dest.root.Remove(tempName); err != nil && !errors.Is(err, os.ErrNotExist) && retErr == nil {
				retErr = fmt.Errorf("remove candidate JSON temporary file: %w", err)
			}
		}
	}()

	if err := encode(f); err != nil {
		_ = f.Close()
		return fmt.Errorf("serialize candidate JSON: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync candidate JSON temporary file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close candidate JSON temporary file: %w", err)
	}

	// Persist the staged directory entry before publication where supported.
	dir, err := dest.root.Open(".")
	if err != nil {
		return fmt.Errorf("open candidate JSON directory for sync: %w", err)
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return fmt.Errorf("sync candidate JSON directory: %w", err)
	}
	if err := dir.Close(); err != nil {
		return fmt.Errorf("close candidate JSON directory: %w", err)
	}

	// Re-check immediately before publication. The platform helper publishes
	// relative to the opened directory and replaces the name rather than
	// following a raced symlink or writing through a raced hard link.
	if err := dest.check(protected); err != nil {
		return err
	}
	if beforeRename != nil {
		if err := beforeRename(dest.root, dest.name); err != nil {
			return fmt.Errorf("candidate JSON publication hook: %w", err)
		}
	}
	if err := renameCandidateAt(dest.root, dest.dir, tempName, dest.name); err != nil {
		return fmt.Errorf("publish candidate JSON: %w", err)
	}
	tempName = "" // the staged inode now has the destination name

	dir, err = dest.root.Open(".")
	if err != nil {
		return fmt.Errorf("open candidate JSON directory after publication: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync candidate JSON directory after publication: %w", err)
	}
	return nil
}
