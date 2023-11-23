package internet

import (
	"context"

	"github.com/xtls/xray-core/common/net"
)

type SecuritySettings interface {
	// secures the given connection with security protocols such as TLS, REALITY, etc.
	Client(ctx context.Context, dest net.Destination, conn net.Conn, expectedProtocol string) (net.Conn, error)
	// secures the given connection with security protocols such as TLS, REALITY, etc.
	Server(conn net.Conn) (net.Conn, error)
}

// MemoryStreamConfig is a parsed form of StreamConfig. This is used to reduce number of Protobuf parsing.
type MemoryStreamConfig struct {
	ProtocolName     string
	ProtocolSettings interface{}
	SecurityType     string
	SecuritySettings SecuritySettings
	SocketSettings   *SocketConfig
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
		mss.SocketSettings = s.SocketSettings
	}

	if s != nil && s.HasSecuritySettings() {
		ess, err := s.GetEffectiveSecuritySettings()
		if err != nil {
			return nil, err
		}
		mss.SecurityType = s.SecurityType
		mss.SecuritySettings = ess.(SecuritySettings)
	}

	return mss, nil
}

type securedListener struct {
	net.Listener

	settings SecuritySettings
}

func NewListener(listener net.Listener, settings SecuritySettings) net.Listener {
	return &securedListener{
		Listener: listener,
		settings: settings,
	}
}

func (l *securedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.settings.Server(conn)
}

func (m *MemoryStreamConfig) ToSecuredListener(listener net.Listener) net.Listener {
	if m.SecuritySettings == nil {
		return listener
	}
	return NewListener(listener, m.SecuritySettings)
}
