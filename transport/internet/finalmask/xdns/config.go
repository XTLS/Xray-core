package xdns

import (
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func (c *Config) UDP() {
}

func (c *Config) WrapPacketConnClient(raw finalmask.PacketConn, level int, levelCount int) (finalmask.PacketConn, error) {
	// _, ok1 := raw.(*internet.FakePacketConn)
	// _, ok2 := raw.(*udphop.UdpHopPacketConn)
	// if level != 0 || ok1 || ok2 {
	// 	return nil, errors.New("xdns requires being at the outermost level")
	// }
	return NewConnClient(c, raw)
}

func (c *Config) WrapPacketConnServer(raw finalmask.PacketConn, level int, levelCount int) (finalmask.PacketConn, error) {
	// if level != 0 {
	// 	return nil, errors.New("xdns requires being at the outermost level")
	// }
	return NewConnServer(c, raw)
}
