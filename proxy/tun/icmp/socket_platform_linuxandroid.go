//go:build linux || android

package icmp

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"runtime"
)

func openEchoSocket(netProto tcpip.NetworkProtocolNumber, dstIP tcpip.Address) (*Socket, error) {
	permissionHint := ""
	if runtime.GOOS == "linux" {
		permissionHint = "Linux ICMP Echo requires either net.ipv4.ping_group_range to allow the Xray process group for udp4/udp6 ping sockets, or CAP_NET_RAW for raw ICMP sockets."
	}
	return openEchoSocketWithCandidates(socketCandidates(netProto, dstIP), permissionHint, isPermissionError)
}

func socketCandidates(netProto tcpip.NetworkProtocolNumber, dstIP tcpip.Address) []socketConfig {
	return append(datagramSocketCandidates(netProto, dstIP, true), rawSocketCandidates(netProto, dstIP)...)
}

func isPermissionError(err error) bool {
	return isPermissionErrorWithFragments(err, "permission denied", "operation not permitted")
}
