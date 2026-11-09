package outbound

import (
	"context"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

type muxDispatcher interface {
	DispatchMux(context.Context, *transport.Link) (bool, error)
}

// Multiplexer selects and owns the configured Mux and XUDP worker pools.
type Multiplexer struct {
	mux    *mux.ClientManager
	xudp   *mux.ClientManager
	udp443 string
}

// NewMultiplexer uses factory to create workers for the enabled pools.
func NewMultiplexer(config *proxyman.MultiplexingConfig, factory func(mux.ClientStrategy) mux.ClientWorkerFactory) *Multiplexer {
	if config == nil || !config.Enabled {
		return nil
	}

	newManager := func(concurrency int32) *mux.ClientManager {
		return &mux.ClientManager{
			Enabled: true,
			Picker: &mux.IncrementalWorkerPicker{
				Factory: factory(mux.ClientStrategy{
					MaxConcurrency: uint32(concurrency),
					MaxConnection:  1024,
				}),
			},
		}
	}

	m := &Multiplexer{udp443: config.XudpProxyUDP443}
	if config.Concurrency >= 0 {
		m.mux = newManager(max(config.Concurrency, 128))
	}
	switch {
	case config.XudpConcurrency < 0:
		m.xudp = &mux.ClientManager{Enabled: false}
	case config.XudpConcurrency > 0:
		m.xudp = newManager(config.XudpConcurrency)
	}
	return m
}

// Dispatch reports whether the session was accepted by Mux or rejected by its UDP policy.
func (m *Multiplexer) Dispatch(ctx context.Context, link *transport.Link) (bool, error) {
	if m == nil {
		return false, nil
	}

	outbounds := session.OutboundsFromContext(ctx)
	target := outbounds[len(outbounds)-1].Target
	manager := m.mux
	if target.Network == net.Network_UDP {
		if target.Port == 443 {
			switch m.udp443 {
			case "reject":
				return true, errors.New("XUDP rejected UDP/443 traffic")
			case "skip":
				return false, nil
			}
		}
		if m.xudp != nil {
			manager = m.xudp
		}
	}
	if manager == nil || !manager.Enabled {
		return false, nil
	}
	return true, manager.Dispatch(ctx, link)
}

// Close stops both worker pools.
func (m *Multiplexer) Close() error {
	if m == nil {
		return nil
	}
	var muxErr, xudpErr error
	if m.mux != nil {
		muxErr = common.Close(m.mux)
	}
	if m.xudp != nil {
		xudpErr = common.Close(m.xudp)
	}
	return errors.Combine(muxErr, xudpErr)
}
