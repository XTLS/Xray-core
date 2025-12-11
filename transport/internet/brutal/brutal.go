//go:build linux

package brutal

import (
	"os"
	"unsafe"

	"github.com/xtls/xray-core/common/net"
	"golang.org/x/sys/unix"
)

//go:linkname setsockopt syscall.setsockopt
func setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error)

const (
	TCP_BRUTAL_PARAMS = 23301
)

type TCPBrutalParams struct {
	Rate     uint64
	CwndGain uint32
}

func setBrutalFD(fd uintptr, sendBPS uint64) error {
	err := unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "brutal")
	if err != nil {
		return err
	}
	params := TCPBrutalParams{
		Rate:     sendBPS,
		CwndGain: 20, // hysteria2 default
	}
	err = setsockopt(int(fd), unix.IPPROTO_TCP, TCP_BRUTAL_PARAMS, unsafe.Pointer(&params), unsafe.Sizeof(params))
	if err != nil {
		return os.NewSyscallError("setsockopt IPPROTO_TCP TCP_BRUTAL_PARAMS", err)
	}
	return nil
}

func SetBrutal(conn *net.TCPConn, sendBPS uint64) error {
	syscallConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	syscallConn.Control(func(fd uintptr) {
		err = setBrutalFD(fd, sendBPS)
	})
	if err != nil {
		return err
	}
	return nil
}
