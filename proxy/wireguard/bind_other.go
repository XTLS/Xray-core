//go:build !linux

package wireguard

import (
	"net"
	"net/netip"

	"github.com/xtls/xray-core/features/stats"
)

func gsoConn(net.PacketConn) (msgWriter, stats.Counter) {
	return nil, nil
}

func sendGSO(msgWriter, [][]byte, netip.AddrPort, stats.Counter) (int, error) {
	return 0, nil
}

func gsoFailed(error) bool {
	return false
}
