package header

import (
	"net"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type headerConn struct {
	finalmask.PacketConn
	header Header
}

func NewConnClient(c *Config, raw finalmask.PacketConn) (finalmask.PacketConn, error) {
	var header Header
	switch HeaderID(c.ID) {
	case DNS:
		var err error
		header, err = NewHeaderDNS(c.Domain)
		if err != nil {
			return nil, err
		}
	case DTLS:
		header = &dtls{}
	case SRTP:
		header = &srtp{}
	case UTP:
		header = &utp{}
	case WECHAT:
		header = &wechat{}
	case WIREGUARD:
		header = &wireguard{}
	default:
		return nil, errors.New("invalid id ", c.ID)
	}
	return &headerConn{
		PacketConn: raw,
		header:     header,
	}, nil
}

func NewConnServer(c *Config, raw finalmask.PacketConn) (finalmask.PacketConn, error) {
	return NewConnClient(c, raw)
}

func (c *headerConn) Size() int {
	return c.header.Size()
}

func (c *headerConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return len(p) - c.header.Size(), nil, nil
}

func (c *headerConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.header.Serialize(p)
	return len(p), nil
}
