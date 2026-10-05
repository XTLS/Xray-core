package httpupgrade

import (
	"bufio"
	"net"

	"github.com/xtls/xray-core/transport/internet/tls"
)

type connection struct {
	net.Conn
	remoteAddr net.Addr
	waiter     tls.ReadWaiter
	// reader has what has been read past the request and is not returned yet
	reader *bufio.Reader
}

func newConnection(conn net.Conn, remoteAddr net.Addr) *connection {
	return &connection{
		Conn:       conn,
		remoteAddr: remoteAddr,
	}
}

func (c *connection) Read(b []byte) (int, error) {
	if c.reader != nil {
		n, err := c.reader.Read(b)
		if c.reader.Buffered() == 0 {
			c.reader = nil
		}
		return n, err
	}
	return c.Conn.Read(b)
}

func (c *connection) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *connection) WaitRead() {
	if c.reader == nil {
		c.waiter.Wait(c.Conn)
	}
}
