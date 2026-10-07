//go:build !linux

package router

import "net"

func asyncDNSReadTCPInfo(net.Conn) asyncDNSTCPInfo {
	return asyncDNSTCPUnavailable("unsupported")
}
