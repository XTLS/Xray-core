package wireguard

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Server struct {
	conf          *DeviceConfig
	ctx           context.Context
	policyManager policy.Manager
	dispatcher    routing.Dispatcher

	tag             string
	src             net.Destination
	sniffingRequest session.SniffingRequest
	streamSettings  *internet.MemoryStreamConfig
	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter

	tun   tun.Device
	stack *stack.Stack
	dev   *device.Device
	mu    sync.Mutex
}

func NewServer(ctx context.Context, conf *DeviceConfig) (*Server, error) {
	v := core.MustFromContext(ctx)
	p := v.GetFeature(policy.ManagerType()).(policy.Manager)
	d := v.GetFeature(routing.DispatcherType()).(routing.Dispatcher)

	inbound := session.InboundFromContext(ctx)
	content := session.ContentFromContext(ctx)
	streamSettings := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig)
	tag := inbound.Tag
	var uplinkCounter stats.Counter
	var downlinkCounter stats.Counter
	if len(tag) > 0 && p.ForSystem().Stats.InboundUplink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "inbound>>>" + tag + ">>>traffic>>>uplink"
		c, _ := stats.GetOrRegisterCounter(statsManager, name)
		if c != nil {
			uplinkCounter = c
		}
	}
	if len(tag) > 0 && p.ForSystem().Stats.InboundDownlink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "inbound>>>" + tag + ">>>traffic>>>downlink"
		c, _ := stats.GetOrRegisterCounter(statsManager, name)
		if c != nil {
			downlinkCounter = c
		}
	}

	if len(conf.Peers) == 0 {
		return nil, errors.New("empty peers")
	}
	for _, peer := range conf.Peers {
		if peer.PublicKey == "" {
			return nil, errors.New("peer without publickey")
		}
	}

	localAddresses := make([]netip.Addr, 0, len(conf.Endpoint))
	for _, localaddress := range conf.Endpoint {
		addr, err := netip.ParseAddr(localaddress)
		if err == nil {
			localAddresses = append(localAddresses, addr)
			continue
		}
		prefix, err := netip.ParsePrefix(localaddress)
		if err == nil {
			localAddresses = append(localAddresses, prefix.Addr())
			continue
		}
		return nil, err
	}

	tun, _, stack, err := CreateNetTUN(localAddresses, nil, int(conf.Mtu), false)
	if err != nil {
		return nil, err
	}

	return &Server{
		conf:          conf,
		ctx:           core.ToBackgroundDetachedContext(ctx),
		policyManager: p,
		dispatcher:    d,

		tag:             inbound.Tag,
		src:             inbound.Source,
		sniffingRequest: content.SniffingRequest,
		streamSettings:  streamSettings,
		uplinkCounter:   uplinkCounter,
		downlinkCounter: downlinkCounter,

		tun:   tun,
		stack: stack,
	}, nil
}

// Network implements proxy.Inbound.Network.
func (*Server) Network() []net.Network {
	return []net.Network{}
}

// Process implements proxy.Inbound.Process.
func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	return nil
}

// Close implements common.Closable.Close.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dev != nil {
		s.dev.Close()
		s.dev = nil
		s.tun = nil
	} else if s.tun != nil {
		s.tun.Close()
		s.tun = nil
	}
	return nil
}

// Start implements common.Runnable.Start.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dev != nil {
		return nil
	}
	if s.src.Address.Family().IsDomain() {
		return errors.New("address is domain")
	}
	listenFunc := func() (net.PacketConn, error) {
		pktConn, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{IP: s.src.Address.IP(), Port: int(s.src.Port)}, s.streamSettings.SocketSettings)
		if err != nil {
			return nil, err
		}
		if s.streamSettings.UdpmaskManager != nil {
			newConn, err := s.streamSettings.UdpmaskManager.WrapPacketConnServer(pktConn)
			if err != nil {
				pktConn.Close()
				return nil, errors.New("mask err").Base(err)
			}
			pktConn = newConn
		}
		if s.uplinkCounter != nil || s.downlinkCounter != nil {
			pktConn = &PacketCounterConnection{
				PacketConn:   pktConn,
				ReadCounter:  s.uplinkCounter,
				WriteCounter: s.downlinkCounter,
			}
		}
		return pktConn, nil
	}
	bind := &bind{
		listenFunc: listenFunc,
	}
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Debug,
				Content:  fmt.Sprintf(format, args...),
			})
		},
		Errorf: func(format string, args ...any) {
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Error,
				Content:  fmt.Sprintf(format, args...),
			})
		},
	}
	dev := device.NewDevice(s.tun, bind, logger)
	var cfg strings.Builder
	cfg.WriteString("private_key=" + s.conf.SecretKey + "\n")
	for _, peer := range s.conf.Peers {
		cfg.WriteString("public_key=" + peer.PublicKey + "\n")
		if peer.PreSharedKey != "" {
			cfg.WriteString("preshared_key=" + peer.PreSharedKey + "\n")
		}
		for _, ip := range peer.AllowedIps {
			cfg.WriteString("allowed_ip=" + ip + "\n")
		}
		if peer.KeepAlive != "" {
			cfg.WriteString("persistent_keepalive_interval=" + peer.KeepAlive + "\n")
		}
	}
	err := dev.IpcSet(cfg.String())
	if err != nil {
		return err
	}
	err = dev.Up()
	if err != nil {
		return err
	}
	s.dev = dev
	createForwarder(s.stack, s.HandleConnection)
	return nil
}

func (s *Server) HandleConnection(conn net.Conn, dest net.Destination) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	ctx = c.ContextWithID(ctx, session.NewID())

	source := net.DestinationFromAddr(conn.RemoteAddr())
	inbound := session.Inbound{
		Name:          "wireguard",
		Tag:           s.tag,
		CanSpliceCopy: 3,
		Source:        source,
	}

	ctx = session.ContextWithInbound(ctx, &inbound)
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: s.sniffingRequest,
	})
	ctx = session.SubContextFromMuxInbound(ctx)

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   inbound.Source,
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
	})
	errors.LogInfo(ctx, "processing from ", source, " to ", dest)

	link := &transport.Link{
		Reader: &buf.TimeoutWrapperReader{Reader: buf.NewReader(conn)},
		Writer: buf.NewWriter(conn),
	}
	if err := s.dispatcher.DispatchLink(ctx, dest, link); err != nil {
		errors.LogError(ctx, errors.New("connection closed").Base(err))
	}
}
