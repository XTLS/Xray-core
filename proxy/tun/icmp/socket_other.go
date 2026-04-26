//go:build !linux && !android && !darwin && !ios && !windows

package icmp

import (
	stdnet "net"

	xnet "github.com/xtls/xray-core/common/net"
	"gvisor.dev/gvisor/pkg/tcpip"
)

func openEchoSocket(netProto tcpip.NetworkProtocolNumber, dstIP tcpip.Address) (*Socket, error) {
	return openEchoSocketWithCandidates(socketCandidates(netProto, dstIP), "", nil)
}

func socketCandidates(netProto tcpip.NetworkProtocolNumber, dstIP tcpip.Address) []socketConfig {
	return append(datagramSocketCandidates(netProto, dstIP, false), rawSocketCandidates(netProto, dstIP)...)
}

func shouldSkipSyntheticReply(s *Socket, srcIP stdnet.IP) (bool, error) {
	if s == nil || !IsDatagramNetwork(s.Network) || len(srcIP) == 0 {
		return false, nil
	}
	return xnet.IsLocal(srcIP)
}
