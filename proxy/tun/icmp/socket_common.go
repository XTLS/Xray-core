package icmp

import (
	stdnet "net"
	"syscall"

	"github.com/xtls/xray-core/transport/internet"
	"gvisor.dev/gvisor/pkg/tcpip"
)

type Socket struct {
	Network               string
	RemoteAddr            stdnet.Addr
	Conn                  stdnet.PacketConn
	AcceptLocalIdentifier bool
}

type socketConfig struct {
	network               string
	controllerNetwork     string
	listenAddr            string
	remoteAddr            stdnet.Addr
	acceptLocalIdentifier bool
}

func OpenEchoSocket(netProto tcpip.NetworkProtocolNumber, dstIP tcpip.Address) (*Socket, error) {
	return openEchoSocket(netProto, dstIP)
}

func (s *Socket) ReplyIdentifier() (uint16, bool) {
	if s == nil || !s.AcceptLocalIdentifier {
		return 0, false
	}
	return DatagramEchoIdentifier(s.Conn.LocalAddr())
}

func applyRawSocketControllers(network, address string, rawConn syscall.RawConn) error {
	internet.ControllersLock.Lock()
	controllers := append([]func(string, string, syscall.RawConn) error(nil), internet.Controllers...)
	internet.ControllersLock.Unlock()

	for _, ctl := range controllers {
		if err := ctl(network, address, rawConn); err != nil {
			return err
		}
	}

	return nil
}
