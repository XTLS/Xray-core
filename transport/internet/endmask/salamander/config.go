package salamander

import (
	"net"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/endmask/salamander/obfs"
)

func (c *Config) WrapConn(raw net.Conn) (net.Conn, error) {
	return nil, errors.New("pkt only")
}

func (c *Config) WrapPacketConn(raw net.PacketConn) (net.PacketConn, error) {
	ob, err := obfs.NewSalamanderObfuscator([]byte(c.Password))
	if err != nil {
		return nil, errors.New("obfs err").Base(err)
	}
	return obfs.WrapPacketConn(raw, ob), nil
}

func (c *Config) Size() int32 {
	return 0
}

func (c *Config) Serialize([]byte) {
}
