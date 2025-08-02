package quic

import (
	"context"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			ServerName:    internalDomain,
			AllowInsecure: true,
		}
	}

	var destAddr *net.UDPAddr
	if dest.Address.Family().IsIP() {
		destAddr = &net.UDPAddr{
			IP:   dest.Address.IP(),
			Port: int(dest.Port),
		}
	} else {
		dialerIp := internet.DestIpAddress()
		if dialerIp != nil {
			destAddr = &net.UDPAddr{
				IP:   dialerIp,
				Port: int(dest.Port),
			}
			errors.LogInfo(ctx, "quic Dial use dialer dest addr: ", destAddr)
		} else {
			addr, err := net.ResolveUDPAddr("udp", dest.NetAddr())
			if err != nil {
				return nil, err
			}
			destAddr = addr
		}
	}

	config := streamSettings.ProtocolSettings.(*Config)

	return openConnection(ctx, destAddr, config, tlsConfig, streamSettings.SocketSettings)
}

func openConnection(ctx context.Context, destAddr net.Addr, config *Config, tlsConfig *tls.Config, sockopt *internet.SocketConfig) (stat.Connection, error) {
	dest := net.DestinationFromAddr(destAddr)
	errors.LogInfo(ctx, "dialing quic to ", dest)
	rawConn, err := internet.DialSystem(ctx, dest, sockopt)
	if err != nil {
		return nil, errors.New("failed to dial to dest: ", err).AtWarning().Base(err)
	}

	quicConfig := &quic.Config{
		KeepAlivePeriod:      0,
		HandshakeIdleTimeout: time.Second * 8,
		MaxIdleTimeout:       time.Second * 300,
		EnableDatagrams:      true,
	}

	var udpConn *net.UDPConn
	switch conn := rawConn.(type) {
	case *net.UDPConn:
		udpConn = conn
	case *internet.PacketConnWrapper:
		udpConn = conn.Conn.(*net.UDPConn)
	default:
		rawConn.Close()
		return nil, errors.New("QUIC with sockopt is unsupported").AtWarning()
	}

	tr := quic.Transport{
		ConnectionIDLength: 12,
		Conn:               udpConn,
	}
	conn, err := tr.Dial(context.Background(), destAddr, tlsConfig.GetTLSConfig(tls.WithDestination(dest)), quicConfig)
	if err != nil {
		udpConn.Close()
		return nil, err
	}

	return NewConnInitReader(ctx, conn, done.New(), destAddr), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
