package splithttp

import "net"

type H1Conn struct {
	UnreadedResponsesCount int
	net.Conn
}

func NewH1Conn(conn net.Conn) *H1Conn {
	return &H1Conn{Conn: conn}
}
