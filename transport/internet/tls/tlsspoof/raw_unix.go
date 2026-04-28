//go:build linux || darwin || freebsd

package tlsspoof

import (
	"net/netip"


	"golang.org/x/sys/unix"
)

func openIPv4RawSocket(dst netip.AddrPort) (int, unix.Sockaddr, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return -1, nil, func(err error, m string) error { return err }(err, "open AF_INET SOCK_RAW")
	}
	err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	if err != nil {
		unix.Close(fd)
		return -1, nil, func(err error, m string) error { return err }(err, "set IP_HDRINCL")
	}
	sockaddr := &unix.SockaddrInet4{Port: int(dst.Port())}
	sockaddr.Addr = dst.Addr().As4()
	return fd, sockaddr, nil
}
