package hysteria2

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"strconv"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/hysteria2/hyconfig"
	hyserver "github.com/xtls/xray-core/proxy/hysteria2/hycore/v2/server"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	vraytls "github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

type inboundHandler struct {
	tag            string
	receiverConfig *proxyman.ReceiverConfig
	proxyConfig    *InboundConfig

	dispatcher routing.Dispatcher

	servers []hyServerHolder
}

type hyServerHolder struct {
	server hyserver.Server
	cancel context.CancelFunc
}

type inboundXrayOptions struct {
	UseRouting *bool `json:"useRouting"`
	UseTLS     *bool `json:"useTLS"`
}

func (c *InboundConfig) BuildInboundHandler(ctx context.Context, tag string, receiver *proxyman.ReceiverConfig) (inbound.Handler, error) {
	h := &inboundHandler{
		tag:            tag,
		receiverConfig: receiver,
		proxyConfig:    c,
	}

	if err := core.RequireFeatures(ctx, func(d routing.Dispatcher) error {
		h.dispatcher = d
		return nil
	}); err != nil {
		return nil, err
	}

	return h, nil
}

func (h *inboundHandler) Tag() string { return h.tag }

func (h *inboundHandler) ReceiverSettings() *serial.TypedMessage {
	return serial.ToTypedMessage(h.receiverConfig)
}

func (h *inboundHandler) ProxySettings() *serial.TypedMessage {
	return serial.ToTypedMessage(h.proxyConfig)
}

func (h *inboundHandler) Start() error {
	if h.receiverConfig.PortList == nil {
		return errors.New("hysteria inbound: port list is empty")
	}

	streamConfig, err := internet.ToMemoryStreamConfig(h.receiverConfig.StreamSettings)
	if err != nil {
		return errors.New("hysteria inbound: failed to parse stream settings").Base(err)
	}

	useRouting, useTLS, rawSettings, err := h.extractSettings()
	if err != nil {
		return err
	}

	for _, pr := range h.receiverConfig.PortList.Range {
		for p := pr.From; p <= pr.To; p++ {
			if err := h.launchServer(streamConfig, useRouting, useTLS, rawSettings, xnet.Port(p)); err != nil {
				_ = h.Close()
				return err
			}
		}
	}
	return nil
}

func (h *inboundHandler) Close() error {
	var errs []error
	for _, srv := range h.servers {
		if srv.cancel != nil {
			srv.cancel()
		}
		if srv.server != nil {
			if err := srv.server.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Combine(errs...)
}

func (h *inboundHandler) extractSettings() (useRouting bool, useTLS bool, settings *structpb.Struct, err error) {
	useRouting = true
	useTLS = true

	if h.proxyConfig.Settings == nil {
		settings = &structpb.Struct{}
		return
	}

	m := h.proxyConfig.Settings.AsMap()
	if rawXray, ok := m["xray"]; ok {
		if optsMap, ok := rawXray.(map[string]any); ok {
			optsBytes, _ := json.Marshal(optsMap)
			var opts inboundXrayOptions
			if json.Unmarshal(optsBytes, &opts) == nil {
				if opts.UseRouting != nil {
					useRouting = *opts.UseRouting
				}
				if opts.UseTLS != nil {
					useTLS = *opts.UseTLS
				}
			}
		}
		delete(m, "xray")
	}
	settings, err = structpb.NewStruct(m)
	return
}

func (h *inboundHandler) launchServer(stream *internet.MemoryStreamConfig, useRouting, useTLS bool, settings *structpb.Struct, port xnet.Port) error {
	addr := h.receiverConfig.Listen.AsAddress()
	if addr == nil {
		addr = xnet.AnyIP
	}

	pktAddr := &net.UDPAddr{
		IP:   addr.IP(),
		Port: int(port),
	}

	listener, err := internet.ListenSystemPacket(context.Background(), pktAddr, stream.SocketSettings)
	if err != nil {
		return errors.New("hysteria inbound: listen UDP failed").Base(err)
	}

	serverCtx, cancel := context.WithCancel(context.Background())
	inboundCtx := session.ContextWithInbound(serverCtx, &session.Inbound{
		Tag:  h.tag,
		Name: "hysteria2",
	})

	serverConfig, err := h.buildServerConfig(inboundCtx, stream, useRouting, useTLS, settings, listener)
	if err != nil {
		cancel()
		_ = listener.Close()
		return err
	}

	srv, err := hyserver.NewServer(serverConfig)
	if err != nil {
		cancel()
		_ = listener.Close()
		return errors.New("hysteria inbound: failed to create server").Base(err)
	}

	h.servers = append(h.servers, hyServerHolder{server: srv, cancel: cancel})
	go func() {
		if err := srv.Serve(); err != nil {
			errors.LogWarningInner(inboundCtx, err, "hysteria inbound serve exited")
		}
	}()
	return nil
}

func (h *inboundHandler) buildServerConfig(ctx context.Context, stream *internet.MemoryStreamConfig, useRouting, useTLS bool, settings *structpb.Struct, listener net.PacketConn) (*hyserver.Config, error) {
	cfgJSON, err := protojson.Marshal(settings)
	if err != nil {
		return nil, errors.New("hysteria inbound: failed to marshal settings").Base(err)
	}

	var raw hyconfig.ServerConfig
	if err := json.Unmarshal(cfgJSON, &raw); err != nil {
		return nil, errors.New("hysteria inbound: invalid settings").Base(err)
	}

	var streamTLS *tls.Config
	if useTLS {
		if cfg := vraytls.ConfigFromStreamSettings(stream); cfg != nil {
			tlsCfg := cfg.GetTLSConfig()
			streamTLS = tlsCfg
		}
	}

	hyCfg, err := raw.Build(listener, hyconfig.BuildOptions{
		UseTLSFromStream: useTLS && streamTLS != nil,
		StreamTLS:        streamTLS,
	})
	if err != nil {
		return nil, err
	}

	if useRouting {
		hyCfg.Outbound = &xrayOutbound{
			dispatcher: h.dispatcher,
			tag:        h.tag,
			ctx:        ctx,
		}
	}
	return hyCfg, nil
}

// xrayOutbound implements hysteria server Outbound interface using Xray dispatcher.
type xrayOutbound struct {
	dispatcher routing.Dispatcher
	tag        string
	ctx        context.Context
}

func (o *xrayOutbound) TCP(reqAddr string) (net.Conn, error) {
	dest, err := parseDestination(reqAddr, xnet.Network_TCP)
	if err != nil {
		return nil, err
	}
	return dispatchConnection(o.ctx, o.dispatcher, o.tag, dest, xnet.Network_TCP)
}

func (o *xrayOutbound) UDP(reqAddr string) (hyserver.UDPConn, error) {
	dest, err := parseDestination(reqAddr, xnet.Network_UDP)
	if err != nil {
		return nil, err
	}
	return newUDPBridge(o.ctx, o.dispatcher, o.tag, dest), nil
}

func parseDestination(addr string, network xnet.Network) (xnet.Destination, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return xnet.Destination{}, errors.New("hysteria outbound: invalid addr ", addr).Base(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return xnet.Destination{}, errors.New("hysteria outbound: invalid port ", portStr).Base(err)
	}
	return xnet.Destination{
		Network: network,
		Address: xnet.ParseAddress(host),
		Port:    xnet.Port(port),
	}, nil
}

func dispatchConnection(ctx context.Context, d routing.Dispatcher, tag string, dest xnet.Destination, network xnet.Network) (net.Conn, error) {
	ur, uw := pipe.New(pipe.OptionsFromContext(ctx)...)
	dr, dw := pipe.New(pipe.OptionsFromContext(ctx)...)

	link := &transport.Link{Reader: ur, Writer: dw}

	go func() {
		ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
			Target: dest,
			Tag:    tag,
		}})
		_ = d.DispatchLink(ctx, dest, link)
	}()

	var readerOpt cnc.ConnectionOption
	if network == xnet.Network_TCP {
		readerOpt = cnc.ConnectionOutputMulti(dr)
	} else {
		readerOpt = cnc.ConnectionOutputMultiUDP(dr)
	}

	return cnc.NewConnection(
		cnc.ConnectionInputMulti(uw),
		readerOpt,
		cnc.ConnectionOnClose(common.ChainedClosable{uw, dw}),
	), nil
}

type udpBridge struct {
	dispatcher routing.Dispatcher
	tag        string
	dest       xnet.Destination
	link       *transport.Link
	uplink     buf.Writer
	downlink   buf.Reader
	pending    buf.MultiBuffer
}

func newUDPBridge(ctx context.Context, d routing.Dispatcher, tag string, dest xnet.Destination) *udpBridge {
	ur, uw := pipe.New()
	dr, dw := pipe.New()
	link := &transport.Link{Reader: ur, Writer: dw}

	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
		Target: dest,
		Tag:    tag,
	}})

	go func() {
		_ = d.DispatchLink(ctx, dest, link)
	}()

	return &udpBridge{
		dispatcher: d,
		tag:        tag,
		dest:       dest,
		link:       link,
		uplink:     uw,
		downlink:   dr,
	}
}

func (u *udpBridge) ReadFrom(b []byte) (int, string, error) {
	if len(u.pending) == 0 {
		mb, err := u.downlink.ReadMultiBuffer()
		if err != nil {
			return 0, "", err
		}
		if len(mb) == 0 {
			return 0, "", errors.New("empty buffer")
		}
		u.pending = mb
	}

	packet := u.pending[0]
	u.pending = u.pending[1:]

	n := copy(b, packet.Bytes())
	addr := u.dest.NetAddr()
	if packet.UDP != nil {
		addr = packet.UDP.NetAddr()
	}
	packet.Release()
	return n, addr, nil
}

func (u *udpBridge) WriteTo(b []byte, addr string) (int, error) {
	dest := u.dest
	if addr != "" {
		if parsed, err := parseDestination(addr, xnet.Network_UDP); err == nil {
			dest = parsed
		}
	}
	packet := buf.FromBytes(append([]byte(nil), b...))
	packet.UDP = &dest
	return len(b), u.uplink.WriteMultiBuffer(buf.MultiBuffer{packet})
}

func (u *udpBridge) Close() error {
	if len(u.pending) > 0 {
		buf.ReleaseMulti(u.pending)
		u.pending = nil
	}
	_ = common.Close(u.link.Writer)
	_ = common.Close(u.link.Reader)
	return nil
}
