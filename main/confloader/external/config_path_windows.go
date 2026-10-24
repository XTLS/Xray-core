//go:build windows

package external

import (
	"os"

	"golang.org/x/sys/windows"
)

func configFilePath(file *os.File) (string, error) {
	raw, err := file.SyscallConn()
	if err != nil {
		return "", err
	}

	var path string
	var pathErr error
	err = raw.Control(func(handle uintptr) {
		// Resolve the opened file itself: Windows junction traversal through
		// filepath.EvalSymlinks can fail after os.Open has already succeeded.
		buffer := make([]uint16, 100)
		for {
			n, err := windows.GetFinalPathNameByHandle(windows.Handle(handle), &buffer[0], uint32(len(buffer)), 0)
			if err != nil {
				pathErr = err
				return
			}
			if n < uint32(len(buffer)) {
				path = windows.UTF16ToString(buffer[:n])
				return
			}
			buffer = make([]uint16, n)
		}
	})
	if err != nil {
		return "", err
	}
	return path, pathErr
}
