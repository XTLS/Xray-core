package internet

import (
	"context"
	reflect "reflect"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

// MemoryStreamConfig is a parsed form of StreamConfig. It is used to reduce the number of Protobuf parses.
type MemoryStreamConfig struct {
	Destination      *net.Destination
	ProtocolName     string
	ProtocolSettings interface{}
	SecurityType     string
	SecuritySettings interface{}
	FinalMask        *finalmask.FinalMask
	QuicParams       *QuicParams
	SocketSettings   *SocketConfig
	DownloadSettings *MemoryStreamConfig
}

// ToMemoryStreamConfig converts a StreamConfig to MemoryStreamConfig. It returns a default non-nil MemoryStreamConfig for nil input.
func ToMemoryStreamConfig(s *StreamConfig) (*MemoryStreamConfig, error) {
	ets, err := s.GetEffectiveTransportSettings()
	if err != nil {
		return nil, err
	}

	mss := &MemoryStreamConfig{
		ProtocolName:     s.GetEffectiveProtocol(),
		ProtocolSettings: ets,
	}

	if s != nil {
		if s.Address != nil {
			mss.Destination = &net.Destination{
				Address: s.Address.AsAddress(),
				Port:    net.Port(s.Port),
				Network: net.Network_TCP,
			}
		}
		mss.SocketSettings = s.SocketSettings
	}

	if s != nil && s.HasSecuritySettings() {
		ess, err := s.GetEffectiveSecuritySettings()
		if err != nil {
			return nil, err
		}
		mss.SecurityType = s.SecurityType
		mss.SecuritySettings = ess
	}

	var tcpMasks []finalmask.TCPMask
	var udpMasks []finalmask.UDPMask
	var sockopt *SocketConfig

	if s != nil {
		for i := range s.Tcpmasks {
			instance := common.Must2(s.Tcpmasks[i].GetInstance())
			tcpMasks = append(tcpMasks, instance.(finalmask.TCPMask))
		}
		for i := range s.Udpmasks {
			instance := common.Must2(s.Udpmasks[i].GetInstance())
			udpMasks = append(udpMasks, instance.(finalmask.UDPMask))
		}
		sockopt = s.SocketSettings
	}

	dialTCP := func(ctx context.Context, dest net.Destination) (net.Conn, error) {
		return DialSystem(ctx, dest, sockopt)
	}
	listen := func(ctx context.Context, addr net.Addr) (net.Listener, error) {
		return ListenSystem(ctx, addr, sockopt)
	}
	dialUDP := func(ctx context.Context, dest net.Destination) (net.PacketConn, error) {
		conn, err := DialSystem(ctx, dest, sockopt)
		if err != nil {
			return nil, err
		}
		var newConn net.PacketConn
		switch c := conn.(type) {
		case *PacketConnWrapper:
			newConn = c.PacketConn
		case *cnc.Connection:
			newConn = &FakePacketConn{Conn: c}
		default:
			panic(reflect.TypeOf(c))
		}
		return newConn, nil
	}
	listenPacket := func(ctx context.Context, addr net.Addr) (net.PacketConn, error) {
		return ListenSystemPacket(ctx, addr, sockopt)
	}
	mss.FinalMask = finalmask.NewFinalMask(tcpMasks, udpMasks, dialTCP, listen, dialUDP, listenPacket)

	if s != nil && s.QuicParams != nil {
		mss.QuicParams = s.QuicParams
	}

	return mss, nil
}
