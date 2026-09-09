//go:build !windows && !darwin && !linux && !android && !ios && !freebsd && !openbsd
// +build !windows,!darwin,!linux,!android,!ios,!freebsd,!openbsd

package internet

func applyOutboundSocketOptions(network string, address string, fd uintptr, config *SocketConfig) error {
	return nil
}

func applyInboundSocketOptions(network string, fd uintptr, config *SocketConfig) error {
	return nil
}

func setReuseAddr(fd uintptr) error {
	return nil
}

func setReusePort(fd uintptr) error {
	return nil
}
