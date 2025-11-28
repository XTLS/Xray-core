package congestion

import (
	"github.com/xtls/xray-core/proxy/hysteria2/hycore/v2/internal/congestion/bbr"
	"github.com/xtls/xray-core/proxy/hysteria2/hycore/v2/internal/congestion/brutal"
	"github.com/apernet/quic-go"
)

func UseBBR(conn *quic.Conn) {
	conn.SetCongestionControl(bbr.NewBbrSender(
		bbr.DefaultClock{},
		bbr.GetInitialPacketSize(conn.RemoteAddr()),
	))
}

func UseBrutal(conn *quic.Conn, tx uint64) {
	conn.SetCongestionControl(brutal.NewBrutalSender(tx))
}
