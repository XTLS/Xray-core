//go:build windows

package icmp

import (
	stdnet "net"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func openEchoSocket(netProto tcpip.NetworkProtocolNumber, dstIP tcpip.Address) (*Socket, error) {
	return openEchoSocketWithCandidates(socketCandidates(netProto, dstIP), "Windows ICMP Echo requires Administrator privileges for raw ICMP sockets.", isPermissionError)
}

func socketCandidates(netProto tcpip.NetworkProtocolNumber, dstIP tcpip.Address) []socketConfig {
	return rawSocketCandidates(netProto, dstIP)
}

func listenEchoSocket(config socketConfig) (stdnet.PacketConn, error) {
	return listenRawEchoSocket(config)
}

func isPermissionError(err error) bool {
	return isPermissionErrorWithFragments(err,
		"permission denied",
		"operation not permitted",
		"access is denied",
		"access permissions",
	)
}

func shouldSkipSyntheticReply(*Socket, stdnet.IP) (bool, error) {
	return false, nil
}
