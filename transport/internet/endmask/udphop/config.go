package udphop

import (
	"net"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/endmask/udphop/udphop"
)

func (c *Config) NewUDPHopPacketConn(listenFunc func() (net.PacketConn, error), raw net.PacketConn) (net.PacketConn, error) {
	addr, err := udphop.ResolveUDPHopAddr(c.Port)
	if err != nil {
		return nil, errors.New("udphop err").Base(err)
	}
	raw, err = udphop.NewUDPHopPacketConn(addr, time.Duration(c.Interval)*time.Second, listenFunc, raw)
	if err != nil {
		return nil, errors.New("udphop err").Base(err)
	}
	return raw, nil
}
