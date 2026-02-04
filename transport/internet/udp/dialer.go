package udp

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
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
				wrapper, ok := conn.(*internet.PacketConnWrapper)
				if !ok {
					conn.Close()
					return nil, errors.New("conn is not PacketConnWrapper")
				}

				raw := wrapper.Conn

				wrapper.Conn, err = streamSettings.UdpmaskManager.WrapPacketConnClient(raw)
				if err != nil {
					raw.Close()
					return nil, errors.New("mask err").Base(err)
				}
			}

			// TODO: handle dialer options
			return conn, nil
		}))
}
