package xpool

import "net"

type SocketConfig struct {
	UserTimeout   int // ms
	KeepAliveIdle int // s
	KeepAliveIntv int // s
	KeepAliveCnt  int
	NoDelay       bool
}

var DefaultSocketConfig = SocketConfig{
	UserTimeout:   3000,
	KeepAliveIdle: 10,
	KeepAliveIntv: 3,
	KeepAliveCnt:  3,
	NoDelay:       true,
}

func ConfigureTCPConn(conn net.Conn, cfg *SocketConfig) error {
	return configureTCP(conn, cfg)
}
