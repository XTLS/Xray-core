package socks

import (
	"net"
	sync "sync"

	"github.com/xtls/xray-core/common/errors"
)

type TempUDPConn struct {
	*net.UDPConn
	once   sync.Once
	remote net.Addr
}

func (c *TempUDPConn) Read(b []byte) (n int, err error) {
	n, addr, err := c.ReadFrom(b)
	if err != nil {
		return 0, err
	}
	c.once.Do(func() {
		c.remote = addr
	})
	return n, nil
}

func (c *TempUDPConn) Write(b []byte) (n int, err error) {
	if c.remote == nil {
		return 0, errors.New("remote address not determined yet")
	}
	return c.UDPConn.WriteTo(b, c.remote)
}

func (c *TempUDPConn) RemoteAddr() net.Addr {
	return c.remote
}
