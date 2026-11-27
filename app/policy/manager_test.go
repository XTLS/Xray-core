package policy_test

import (
	"context"
	"testing"
	"time"

	. "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/features/policy"
)

func TestPolicy(t *testing.T) {
	manager, err := New(context.Background(), &Config{
		Level: map[uint32]*Policy{
			0: {
				Timeout: &Policy_Timeout{
					Handshake: &Second{
						Value: 2,
					},
				},
			},
			2: {
				Timeout: &Policy_Timeout{
					UdpIdle: &Second{
						Value: 300,
					},
				},
			},
		},
	})
	common.Must(err)

	pDefault := policy.SessionDefault()

	{
		p := manager.ForLevel(0)
		if p.Timeouts.Handshake != 2*time.Second {
			t.Error("expect 2 sec timeout, but got ", p.Timeouts.Handshake)
		}
		if p.Timeouts.ConnectionIdle != pDefault.Timeouts.ConnectionIdle {
			t.Error("expect ", pDefault.Timeouts.ConnectionIdle, " sec timeout, but got ", p.Timeouts.ConnectionIdle)
		}
		if p.Timeouts.UDPIdle != time.Minute {
			t.Error("expect 60 sec UDP idle timeout, but got ", p.Timeouts.UDPIdle)
		}
	}

	{
		p := manager.ForLevel(2)
		if p.Timeouts.UDPIdle != 300*time.Second {
			t.Error("expect 300 sec UDP idle timeout, but got ", p.Timeouts.UDPIdle)
		}
		if p.Timeouts.ConnectionIdle != pDefault.Timeouts.ConnectionIdle {
			t.Error("expect ", pDefault.Timeouts.ConnectionIdle, " sec timeout, but got ", p.Timeouts.ConnectionIdle)
		}
	}

	{
		p := manager.ForLevel(1)
		if p.Timeouts.Handshake != pDefault.Timeouts.Handshake {
			t.Error("expect ", pDefault.Timeouts.Handshake, " sec timeout, but got ", p.Timeouts.Handshake)
		}
		if p.Timeouts.UDPIdle != pDefault.Timeouts.UDPIdle {
			t.Error("expect ", pDefault.Timeouts.UDPIdle, " sec UDP idle timeout, but got ", p.Timeouts.UDPIdle)
		}
	}
}
