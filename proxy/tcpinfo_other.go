//go:build !linux && !android

package proxy

import "net"

func tcpBytesReceived(net.Conn) (int64, bool) {
	return 0, false
}
