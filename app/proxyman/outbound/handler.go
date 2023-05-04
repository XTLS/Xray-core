package outbound

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
)

func getStatCounter(v *core.Instance, tag string) (stats.Counter, stats.Counter) {
	var uplinkCounter stats.Counter
	var downlinkCounter stats.Counter

	policy := v.GetFeature(policy.ManagerType()).(policy.Manager)
	if len(tag) > 0 && policy.ForSystem().Stats.OutboundUplink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "outbound>>>" + tag + ">>>traffic>>>uplink"
		c, _ := stats.GetOrRegisterCounter(statsManager, name)
		if c != nil {
			uplinkCounter = c
		}
	}
	if len(tag) > 0 && policy.ForSystem().Stats.OutboundDownlink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "outbound>>>" + tag + ">>>traffic>>>downlink"
		c, _ := stats.GetOrRegisterCounter(statsManager, name)
		if c != nil {
			downlinkCounter = c
		}
	}

	return uplinkCounter, downlinkCounter
}

// Handler is an implements of outbound.Handler.
type Handler struct {
	tag             string
	senderSettings  *proxyman.SenderConfig
	streamSettings  *internet.MemoryStreamConfig
	proxy           proxy.Outbound
	outboundManager outbound.Manager
	mux             *mux.ClientManager
	xudp            *mux.ClientManager
	udp443          string
	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter
}

// NewHandler creates a new Handler based on the given configuration.
func NewHandler(ctx context.Context, config *core.OutboundHandlerConfig) (outbound.Handler, error) {
	v := core.MustFromContext(ctx)
	uplinkCounter, downlinkCounter := getStatCounter(v, config.Tag)
	h := &Handler{
		tag:             config.Tag,
		outboundManager: v.GetFeature(outbound.ManagerType()).(outbound.Manager),
		uplinkCounter:   uplinkCounter,
		downlinkCounter: downlinkCounter,
	}

	if config.SenderSettings != nil {
		senderSettings, err := config.SenderSettings.GetInstance()
		if err != nil {
			return nil, err
		}
		switch s := senderSettings.(type) {
		case *proxyman.SenderConfig:
			h.senderSettings = s
			mss, err := internet.ToMemoryStreamConfig(s.StreamSettings)
			if err != nil {
				return nil, newError("failed to parse stream settings").Base(err).AtWarning()
			}
			h.streamSettings = mss
		default:
			return nil, newError("settings is not SenderConfig")
		}
	}

	proxyConfig, err := config.ProxySettings.GetInstance()
	if err != nil {
		return nil, err
	}

	rawProxyHandler, err := common.CreateObject(ctx, proxyConfig)
	if err != nil {
		return nil, err
	}

	proxyHandler, ok := rawProxyHandler.(proxy.Outbound)
	if !ok {
		return nil, newError("not an outbound handler")
	}

	if h.senderSettings != nil && h.senderSettings.MultiplexSettings != nil {
		if config := h.senderSettings.MultiplexSettings; config.Enabled {
			if config.Concurrency < 0 {
				h.mux = &mux.ClientManager{Enabled: false}
			}
			if config.Concurrency == 0 {
				config.Concurrency = 8 // same as before
			}
			if config.Concurrency > 0 {
				h.mux = &mux.ClientManager{
					Enabled: true,
					Picker: &mux.IncrementalWorkerPicker{
						Factory: &mux.DialingWorkerFactory{
							Proxy:  proxyHandler,
							Dialer: h,
							Strategy: mux.ClientStrategy{
								MaxConcurrency: uint32(config.Concurrency),
								MaxConnection:  128,
							},
						},
					},
				}
			}
			if config.XudpConcurrency < 0 {
				h.xudp = &mux.ClientManager{Enabled: false}
			}
			if config.XudpConcurrency == 0 {
				h.xudp = nil // same as before
			}
			if config.XudpConcurrency > 0 {
				h.xudp = &mux.ClientManager{
					Enabled: true,
					Picker: &mux.IncrementalWorkerPicker{
						Factory: &mux.DialingWorkerFactory{
							Proxy:  proxyHandler,
							Dialer: h,
							Strategy: mux.ClientStrategy{
								MaxConcurrency: uint32(config.XudpConcurrency),
								MaxConnection:  128,
							},
						},
					},
				}
			}
			h.udp443 = config.XudpProxyUDP443
		}
	}

	h.proxy = proxyHandler
	return h, nil
}

// Tag implements outbound.Handler.
func (h *Handler) Tag() string {
	return h.tag
}

// Dispatch implements proxy.Outbound.Dispatch.
func (h *Handler) Dispatch(ctx context.Context, link *transport.Link) {
	outbound := session.OutboundFromContext(ctx)
	if outbound.Target.Network == net.Network_UDP && outbound.OriginalTarget.Address != nil && outbound.OriginalTarget.Address != outbound.Target.Address {
		link.Reader = &buf.EndpointOverrideReader{Reader: link.Reader, Dest: outbound.Target.Address, OriginalDest: outbound.OriginalTarget.Address}
		link.Writer = &buf.EndpointOverrideWriter{Writer: link.Writer, Dest: outbound.Target.Address, OriginalDest: outbound.OriginalTarget.Address}
	}
	if h.mux != nil {
		test := func(err error) {
			if err != nil {
				err := newError("failed to process mux outbound traffic").Base(err)
				session.SubmitOutboundErrorToOriginator(ctx, err)
				err.WriteToLog(session.ExportIDToError(ctx))
				common.Interrupt(link.Writer)
			}
		}
		if outbound.Target.Network == net.Network_UDP && outbound.Target.Port == 443 {
			switch h.udp443 {
			case "reject":
				test(newError("XUDP rejected UDP/443 traffic").AtInfo())
				return
			case "skip":
				goto out
			}
		}
		if h.xudp != nil && outbound.Target.Network == net.Network_UDP {
			if !h.xudp.Enabled {
				goto out
			}
			test(h.xudp.Dispatch(ctx, link))
			return
		}
		if h.mux.Enabled {
			test(h.mux.Dispatch(ctx, link))
			return
		}
	}
out:
	err := h.proxy.Process(ctx, link, h)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, context.Canceled) {
			err = nil
		}
	}
	if err != nil {
		// Ensure outbound ray is properly closed.
		err := newError("failed to process outbound traffic").Base(err)
		session.SubmitOutboundErrorToOriginator(ctx, err)
		err.WriteToLog(session.ExportIDToError(ctx))
		common.Interrupt(link.Writer)
	} else {
		common.Close(link.Writer)
	}
	common.Interrupt(link.Reader)
}

// Address implements internet.Dialer.
func (h *Handler) Address() net.Address {
	if h.senderSettings == nil || h.senderSettings.Via == nil {
		return nil
	}
	return h.senderSettings.Via.AsAddress()
}

// Dial implements internet.Dialer.
func (h *Handler) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	if h.senderSettings != nil {
		if h.senderSettings.ProxySettings.HasTag() {
			tag := h.senderSettings.ProxySettings.Tag
			handler := h.outboundManager.GetHandler(tag)
			if handler != nil {
				newError("proxying to ", tag, " for dest ", dest).AtDebug().WriteToLog(session.ExportIDToError(ctx))
				ctx = session.ContextWithOutbound(ctx, &session.Outbound{
					Target: dest,
				})

				opts := pipe.OptionsFromContext(ctx)
				uplinkReader, uplinkWriter := pipe.New(opts...)
				downlinkReader, downlinkWriter := pipe.New(opts...)

				go handler.Dispatch(ctx, &transport.Link{Reader: uplinkReader, Writer: downlinkWriter})
				conn := cnc.NewConnection(cnc.ConnectionInputMulti(uplinkWriter), cnc.ConnectionOutputMulti(downlinkReader))

				if config := tls.ConfigFromStreamSettings(h.streamSettings); config != nil {
					tlsConfig := config.GetTLSConfig(tls.WithDestination(dest))
					conn = tls.Client(conn, tlsConfig)
				}

				return h.getStatCouterConnection(conn), nil
			}

			newError("failed to get outbound handler with tag: ", tag).AtWarning().WriteToLog(session.ExportIDToError(ctx))
		}

		if h.senderSettings.Via != nil {
			outbound := session.OutboundFromContext(ctx)
			if outbound == nil {
				outbound = new(session.Outbound)
				ctx = session.ContextWithOutbound(ctx, outbound)
			}
			outbound.Gateway = h.senderSettings.Via.AsAddress()
		}
	}

	if conn, err := h.getUoTConnection(ctx, dest); err != os.ErrInvalid {
		return conn, err
	}

	conn, err := internet.Dial(ctx, dest, h.streamSettings)
	conn = h.getStatCouterConnection(conn)
	outbound := session.OutboundFromContext(ctx)
	if outbound != nil {
		outbound.Conn = conn
	}
	return conn, err
}

func (h *Handler) getStatCouterConnection(conn stat.Connection) stat.Connection {
	if h.uplinkCounter != nil || h.downlinkCounter != nil {
		return &stat.CounterConnection{
			Connection:   conn,
			ReadCounter:  h.downlinkCounter,
			WriteCounter: h.uplinkCounter,
		}
	}
	return conn
}

// GetOutbound implements proxy.GetOutbound.
func (h *Handler) GetOutbound() proxy.Outbound {
	return h.proxy
}

// Start implements common.Runnable.
func (h *Handler) Start() error {
	return nil
}

// Close implements common.Closable.
func (h *Handler) Close() error {
	common.Close(h.mux)
	return nil
}
