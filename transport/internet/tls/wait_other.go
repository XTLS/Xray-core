//go:build !unix

package tls

import "runtime"

// readable returns false if there is nothing to read from fd.
func readable(fd uintptr) bool {
	// On Windows rawConn.Read then waits with a read of zero bytes, and asking first would cost every wait a syscall.
	// Elsewhere there is no way to tell, so nothing waits.
	return runtime.GOOS != "windows"
}
