//go:build linux || android

package icmp

import (
	stdnet "net"

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

var localIPChecker = isLocalInterfaceIP

func shouldSkipSyntheticReply(s *Socket, srcIP stdnet.IP) (bool, error) {
	if s == nil || len(srcIP) == 0 {
		return false, nil
	}

	isLocal, err := localIPChecker(srcIP)
	if err != nil || !isLocal {
		return isLocal, err
	}

	return shouldSkipSyntheticReplyForLinuxAndroid(runtime.GOOS, s.Network), nil
}

func shouldSkipSyntheticReplyForLinuxAndroid(goos, network string) bool {
	if goos == "linux" {
		return true
	}
	return IsDatagramNetwork(network)
}

func isLocalInterfaceIP(ip stdnet.IP) (bool, error) {
	addrs, err := stdnet.InterfaceAddrs()
	if err != nil {
		return false, err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*stdnet.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.Equal(ip) {
			return true, nil
		}
	}
	return false, nil
}
