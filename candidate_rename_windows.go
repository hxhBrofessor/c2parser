//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

type fileRenameInformation struct {
	ReplaceIfExists byte
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [1]uint16
}

var setFileInformationByHandle = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetFileInformationByHandle")

// renameCandidateAt opens the staged inode with DELETE access, confirms that
// the path still identifies the Root-relative staged file, then renames that
// handle relative to the already-open destination directory. This avoids
// re-resolving a replaced parent path; replacement errors leave the old name
// intact and are returned without a delete-then-rename fallback.
func renameCandidateAt(root *os.Root, dir *os.File, oldName, newName string) error {
	oldPath, err := windows.UTF16PtrFromString(filepath.Join(root.Name(), oldName))
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(oldPath, 0x00010000, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)

	rootInfo, err := root.Stat(oldName)
	if err != nil {
		return fmt.Errorf("inspect staged candidate JSON: %w", err)
	}
	opened := os.NewFile(uintptr(h), oldName)
	openedInfo, err := opened.Stat()
	runtime.SetFinalizer(opened, nil) // the handle is closed by windows.CloseHandle above
	if err != nil {
		return fmt.Errorf("stat staged candidate JSON handle: %w", err)
	}
	if !os.SameFile(rootInfo, openedInfo) {
		return fmt.Errorf("staged candidate JSON path changed before publication")
	}

	name, err := windows.UTF16FromString(newName)
	if err != nil {
		return err
	}
	const fileRenameInfoClass = 3
	nameBytes := (len(name) - 1) * 2
	offset := int(unsafe.Offsetof(fileRenameInformation{}.FileName))
	byteLen := offset + nameBytes
	words := make([]uintptr, (byteLen+int(unsafe.Sizeof(uintptr(0)))-1)/int(unsafe.Sizeof(uintptr(0))))
	info := (*fileRenameInformation)(unsafe.Pointer(&words[0]))
	info.ReplaceIfExists = 1
	info.RootDirectory = windows.Handle(dir.Fd())
	info.FileNameLength = uint32(nameBytes)
	copy(unsafe.Slice(&info.FileName[0], len(name)-1), name[:len(name)-1])
	ret, _, callErr := setFileInformationByHandle.Call(uintptr(h), fileRenameInfoClass, uintptr(unsafe.Pointer(info)), uintptr(byteLen))
	runtime.KeepAlive(words)
	if ret == 0 {
		if callErr != windows.ERROR_SUCCESS {
			return fmt.Errorf("atomic candidate JSON rename: %w", callErr)
		}
		return fmt.Errorf("atomic candidate JSON rename failed")
	}
	return nil
}
