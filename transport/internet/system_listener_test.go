package internet_test

import (
	"context"
	"net"
	"syscall"
	"testing"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/sagernet/sing/common/control"
)

func TestRegisterListenerController(t *testing.T) {
	var gotFd uintptr

	common.Must(internet.RegisterListenerController(func(network, address string, conn syscall.RawConn) error {
		return control.Raw(conn, func(fd uintptr) error {
			gotFd = fd
			return nil
		})
	}))

	conn, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{
		IP: net.IPv4zero,
	}, nil)
	common.Must(err)
	common.Must(conn.Close())

	if gotFd == 0 {
		t.Error("expected none-zero fd, but actually 0")
	}
}
