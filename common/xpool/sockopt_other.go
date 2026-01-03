//go:build !linux

package xpool

import "net"

func configureTCP(conn net.Conn, cfg *SocketConfig) error {
	return nil
}
