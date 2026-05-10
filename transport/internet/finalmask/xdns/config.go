package xdns

import (
	"net"
)

func (c *Config) UDP() {
}

func (c *Config) WrapPacketConnClient(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	// _, ok1 := raw.(*internet.FakePacketConn)
	// _, ok2 := raw.(*udphop.UdpHopPacketConn)
	// if level != 0 || ok1 || ok2 {
	// 	return nil, errors.New("xdns requires being at the outermost level")
	// }
	return NewConnClient(c, raw)
}

func (c *Config) WrapPacketConnServer(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	// if level != 0 {
	// 	return nil, errors.New("xdns requires being at the outermost level")
	// }
	return NewConnServer(c, raw)
}
