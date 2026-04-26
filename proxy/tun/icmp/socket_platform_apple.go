//go:build darwin || ios

package icmp

import (
	"gvisor.dev/gvisor/pkg/tcpip"
)

func openEchoSocket(netProto tcpip.NetworkProtocolNumber, dstIP tcpip.Address) (*Socket, error) {
	return openEchoSocketWithCandidates(socketCandidates(netProto, dstIP), "", nil)
}

func socketCandidates(netProto tcpip.NetworkProtocolNumber, dstIP tcpip.Address) []socketConfig {
	return append(datagramSocketCandidates(netProto, dstIP, false), rawSocketCandidates(netProto, dstIP)...)
}
