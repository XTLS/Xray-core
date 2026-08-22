package xicmp

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/hysteria/udphop"
)

func (c *Config) UDP() {
}

func (c *Config) WrapPacketConnClient(raw finalmask.PacketConn, level int, levelCount int) (finalmask.PacketConn, error) {
	under := finalmask.UnwrapUdpMask(raw)
	_, ok1 := under.(*internet.FakePacketConn)
	_, ok2 := under.(*udphop.UdpHopPacketConn)
	if level != 0 || ok1 || ok2 {
		return nil, errors.New("xicmp requires being at the outermost level")
	}
	return NewConnClient(c, raw)
}

func (c *Config) WrapPacketConnServer(raw finalmask.PacketConn, level int, levelCount int) (finalmask.PacketConn, error) {
	if level != 0 {
		return nil, errors.New("xicmp requires being at the outermost level")
	}
	return NewConnServer(c, raw)
}
