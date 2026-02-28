//go:build js || netbsd || openbsd || solaris
// +build js netbsd openbsd solaris

package internet

func applyOutboundSocketOptions(network string, address string, fd uintptr, config *SocketConfig) error {
	return nil
}

func applyInboundSocketOptions(network string, fd uintptr, config *SocketConfig) error {
	return nil
}

func bindAddr(fd uintptr, ip []byte, port uint32) error {
	return nil
}

func setReuseAddr(fd uintptr) error {
	return nil
}

func setReusePort(fd uintptr) error {
	return nil
}

func setsockoptInt(fd uintptr, level, opt, value int) error {
	return nil
}

func setsockoptString(fd uintptr, level, opt int, s string) error {
	return nil
}
