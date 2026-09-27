//go:build !linux

package rawpacket

// attachBPFFilter is a no-op on platforms without SO_ATTACH_FILTER
// (darwin/freebsd raw sockets do not support classic-BPF attachment).
func attachBPFFilter(fd int, proto uint8) {}
