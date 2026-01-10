package udphop

import (
	"net"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/endmask/udphop/udphop"
)

func (c *Config) WrapConnClient(raw net.Conn) (net.Conn, error) {
	return raw, nil
}

func (c *Config) WrapConnServer(raw net.Conn) (net.Conn, error) {
	return raw, nil
}

func (c *Config) WrapPacketConnClient(raw net.PacketConn) (net.PacketConn, error) {
	addr, err := udphop.ResolveUDPHopAddr(c.Port)
	if err != nil {
		return nil, errors.New("udphop err").Base(err)
	}
	raw, err = udphop.NewUDPHopPacketConn(addr, time.Duration(c.Interval)*time.Second, func() (net.PacketConn, error) {
		return raw, nil
	})
	if err != nil {
		return nil, errors.New("udphop err").Base(err)
	}
	return raw, nil
}

func (c *Config) WrapPacketConnServer(raw net.PacketConn) (net.PacketConn, error) {
	return raw, nil
}

func (c *Config) Size() int32 {
	return 0
}

func (c *Config) Serialize([]byte) {
}
