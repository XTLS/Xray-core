package congestion

import (
	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/brutal"
)

func UseBBR(debugLog bool, conn *quic.Conn) {
	conn.SetCongestionControl(bbr.NewBbrSender(
		debugLog,
		bbr.DefaultClock{},
		bbr.GetInitialPacketSize(conn.RemoteAddr()),
	))
}

func UseBrutal(debugLog bool, conn *quic.Conn, tx uint64) {
	conn.SetCongestionControl(brutal.NewBrutalSender(debugLog, tx))
}
