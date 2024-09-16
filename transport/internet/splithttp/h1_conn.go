package splithttp

import (
	"bufio"
	"net"
)

type H1Conn struct {
	UnreadedResponsesCount int
	// To reuse response reader, so we won't lose data
	// If some EOF will accure
	RespBufReader *bufio.Reader
	net.Conn
}

func NewH1Conn(conn net.Conn) *H1Conn {
	return &H1Conn{
		RespBufReader: bufio.NewReader(conn),
		Conn:          conn,
	}
}
