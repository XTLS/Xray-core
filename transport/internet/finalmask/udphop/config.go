package udphop

import (
	"net"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func (c *Config) HandleDial() {}

func (c *Config) WrapPacketConnClient(conn net.PacketConn, dialer *finalmask.Dialer) (net.PacketConn, error) {
	return NewUDPHopConn(c, conn)
}

func (c *Config) WrapPacketConnServer(conn net.PacketConn) (net.PacketConn, error) {
	return nil, errors.New("udphop: client only")
}
