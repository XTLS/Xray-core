package internet

import (
	"context"
	stderrors "errors"
	"io"
	"reflect"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

// MemoryStreamConfig is a parsed form of StreamConfig. It is used to reduce the number of Protobuf parses.
type MemoryStreamConfig struct {
	// A MemoryStreamConfig with registered resources must not be copied.
	closeMu    sync.Mutex
	closeDone  chan struct{}
	closeHooks []func() error
	closeErr   error

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
	if s != nil && (len(s.Tcpmasks) != 0 || len(s.Udpmasks) != 0) {
		var tcpMasks []finalmask.TCPMask
		var udpMasks []finalmask.UDPMask

		for i := range s.Tcpmasks {
			instance := common.Must2(s.Tcpmasks[i].GetInstance())
			tcpMasks = append(tcpMasks, instance.(finalmask.TCPMask))
		}
		for i := range s.Udpmasks {
			instance := common.Must2(s.Udpmasks[i].GetInstance())
			udpMasks = append(udpMasks, instance.(finalmask.UDPMask))
		}

		dialTCP := func(ctx context.Context, dest net.Destination) (net.Conn, error) {
			return DialSystem(ctx, dest, mss.SocketSettings)
		}
		listen := func(ctx context.Context, addr net.Addr) (net.Listener, error) {
			return ListenSystem(ctx, addr, mss.SocketSettings)
		}
		dialUDP := func(ctx context.Context, dest net.Destination) (net.PacketConn, net.Addr, error) {
			conn, err := DialSystem(ctx, dest, mss.SocketSettings)
			if err != nil {
				return nil, nil, err
			}
			var newConn net.PacketConn
			var udpAddr net.Addr
			switch c := conn.(type) {
			case *net.PacketConnWrapper:
				newConn = c.PacketConn
				udpAddr = conn.RemoteAddr()
			case *cnc.Connection:
				newConn = &FakePacketConn{Conn: c}
				udpAddr = &net.UDPAddr{IP: []byte{0, 0, 0, 0}, Port: 0}
			default:
				panic(reflect.TypeOf(c))
			}
			return newConn, udpAddr, nil
		}
		listenPacket := func(ctx context.Context, addr net.Addr) (net.PacketConn, error) {
			return ListenSystemPacket(ctx, addr, mss.SocketSettings)
		}
		mss.FinalMask = finalmask.NewFinalMask(tcpMasks, udpMasks, dialTCP, listen, dialUDP, listenPacket)
	}

	if s != nil && s.QuicParams != nil {
		mss.QuicParams = s.QuicParams
	}

	return mss, nil
}

// OnClose registers cleanup for a transport resource owned by these settings.
// On failure the caller retains ownership and must release the resource.
// Hooks must not call Close on these same settings.
func (s *MemoryStreamConfig) OnClose(close func() error) error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closeDone != nil {
		return io.ErrClosedPipe
	}
	s.closeHooks = append(s.closeHooks, close)
	return nil
}

// IsClosed reports whether cleanup has started, including while it is pending.
func (s *MemoryStreamConfig) IsClosed() bool {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closeDone != nil
}

// Close prevents new registrations and waits for all registered cleanup.
// Direct transport callers own this lifetime; proxyman closes it with its handler.
func (s *MemoryStreamConfig) Close() error {
	s.closeMu.Lock()
	if done := s.closeDone; done != nil {
		s.closeMu.Unlock()
		<-done
		return s.closeErr
	}
	s.closeDone = make(chan struct{})
	hooks := s.closeHooks
	s.closeHooks = nil
	s.closeMu.Unlock()
	var errs []error
	for _, close := range hooks {
		errs = append(errs, close())
	}
	s.closeErr = stderrors.Join(errs...)
	close(s.closeDone)
	return s.closeErr
}
