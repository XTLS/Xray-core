package salamander

import (
	"net"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask/salamander/obfs"
)

func (c *Config) UDP() {
}

func (c *Config) WrapConnClient(raw net.Conn) (net.Conn, error) {
	return raw, nil
}

func (c *Config) WrapConnServer(raw net.Conn) (net.Conn, error) {
	return raw, nil
}

func (c *Config) WrapPacketConnClient(raw net.PacketConn) (net.PacketConn, error) {
	ob, err := obfs.NewSalamanderObfuscator([]byte(c.Password))
	if err != nil {
		return nil, errors.New("salamander err").Base(err)
	}
	return obfs.WrapPacketConn(raw, ob), nil
}

func (c *Config) WrapPacketConnServer(raw net.PacketConn) (net.PacketConn, error) {
	ob, err := obfs.NewSalamanderObfuscator([]byte(c.Password))
	if err != nil {
		return nil, errors.New("salamander err").Base(err)
	}
	return obfs.WrapPacketConn(raw, ob), nil
}

func (c *Config) Size() int {
	return 0
}

func (c *Config) Serialize([]byte) {
}
