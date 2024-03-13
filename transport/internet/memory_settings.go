package internet

import (
	"syscall"
	sing_common "github.com/sagernet/sing/common"
	"github.com/xtls/xray-core/common/net"
)

// MemoryStreamConfig is a parsed form of StreamConfig. This is used to reduce number of Protobuf parsing.
type MemoryStreamConfig struct {
	ProtocolName     string
	ProtocolSettings interface{}
	SecurityType     string
	SecuritySettings interface{}
	SocketSettings   *SocketConfig
}

func (m *MemoryStreamConfig) ApplyBrutalSettings(conn net.Conn) {
	if m.SocketSettings != nil && m.SocketSettings.TcpCongestion == "brutal" {
		sc, loaded := sing_common.Cast[syscall.Conn](conn)
		if loaded {
			if rawConn, e0 := sc.SyscallConn(); e0 != nil {
				newError("sc.SyscallConn failed ", e0).AtError().WriteToLog()
			} else {
				if e1 := rawConn.Control(func(fd uintptr) {
					if e2 := ApplyBrutalParams(int(fd), m.SocketSettings); e2 != nil {
						newError("internet.ApplyBrutalParams failed ", e2).AtError().WriteToLog()
					}
				}); e1 != nil {
					newError("rawConn.Control failed ", e1).AtError().WriteToLog()
				}
			}
		} else {
			newError("cast conn to syscall.Conn failed").AtWarning().WriteToLog()
		}
		newError("Brutal Rate: ", m.SocketSettings.BrutalRate, ", Gain: ", m.SocketSettings.BrutalGain).WriteToLog()
	}
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
		mss.SecuritySettings = ess
	}

	return mss, nil
}
