package httpupgrade

import (
	"net"

	"github.com/xtls/xray-core/transport/internet/stat"
)

type connection struct {
	net.Conn
	remoteAddr net.Addr
	remainData []byte
}

func newConnection(conn net.Conn, remoteAddr net.Addr, remainData []byte) stat.Connection {
	return stat.Connection(&connection{
		Conn:       conn,
		remoteAddr: remoteAddr,
		remainData: remainData,
	})
}

func (c *connection) Read(p []byte) (int, error) {
	if len(c.remainData) > 0 {
		n := copy(p, c.remainData)
		c.remainData = c.remainData[n:]
		if len(c.remainData) == 0 {
			c.remainData = nil
		}
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *connection) RemoteAddr() net.Addr {
	return c.remoteAddr
}
