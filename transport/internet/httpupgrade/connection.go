package httpupgrade

import "net"

type connnection struct {
	net.Conn
	remoteAddr net.Addr
}

func newConnection(conn net.Conn, remoteAddr net.Addr) *connnection {
	return &connnection{
		Conn:       conn,
		remoteAddr: remoteAddr,
	}
}

func (c *connnection) RemoteAddr() net.Addr {
	return c.remoteAddr
}
