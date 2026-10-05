//go:build unix

package tls

import "golang.org/x/sys/unix"

// readable returns false if there is nothing to read from fd, not even an error.
func readable(fd uintptr) bool {
	fds := [1]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(fds[:], 0)
		if err != unix.EINTR {
			return n != 0
		}
	}
}
