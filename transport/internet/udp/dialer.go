package udp

import (
	"context"
	"reflect"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName,
		func(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
			var sockopt *internet.SocketConfig
			if streamSettings != nil {
				sockopt = streamSettings.SocketSettings
			}
			conn, err := internet.DialSystem(ctx, dest, sockopt)
			if err != nil {
				return nil, err
			}

			if streamSettings != nil && streamSettings.UdpmaskManager != nil {
				var pktConn net.PacketConn
				var udpAddr *net.UDPAddr
				switch c := conn.(type) {
				case *internet.PacketConnWrapper:
					pktConn = c.PacketConn
					udpAddr = c.RemoteAddr().(*net.UDPAddr)
				case *cnc.Connection:
					pktConn = &internet.FakePacketConn{Conn: c}
					udpAddr = &net.UDPAddr{IP: c.RemoteAddr().(*net.TCPAddr).IP, Port: c.RemoteAddr().(*net.TCPAddr).Port}
				default:
					panic(reflect.TypeOf(c))
				}
				newConn, err := streamSettings.UdpmaskManager.WrapPacketConnClient(pktConn)
				if err != nil {
					pktConn.Close()
					return nil, errors.New("mask err").Base(err)
				}
				pktConn = newConn
				conn = &internet.PacketConnWrapper{
					PacketConn: pktConn,
					Dest:       udpAddr,
				}
			}

			return conn, nil
		}))
}
