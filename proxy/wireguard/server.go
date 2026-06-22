package wireguard

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
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

// wgIpcSetter abstracts the IPC surface of *device.Device used by the
// UserManager methods. The interface makes the peer management logic
// independently testable without a live WireGuard device.
type wgIpcSetter interface {
	IpcSet(string) error
}

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

	// UserManager state: peers indexed by email and by tunnel IP.
	peers     sync.Map    // email (or public key) → *protocol.MemoryUser
	peersByIP sync.Map    // netip.Addr → *protocol.MemoryUser
	peerCount atomic.Int64

	// ipcOverride is non-nil only in tests. When set it is used instead of
	// s.dev for IpcSet calls, allowing UserManager logic to be tested without
	// a live WireGuard device.
	ipcOverride wgIpcSetter
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

	s := &Server{
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
	}

	// Seed peer maps from the static config so that GetUser / GetUsers work
	// for peers configured at startup, not only for dynamically added ones.
	for _, peer := range conf.Peers {
		if peer.PublicKey == "" {
			continue
		}
		mu := &protocol.MemoryUser{
			Email: peer.PublicKey,
			Account: &MemoryAccount{
				PublicKey:    peer.PublicKey,
				PreSharedKey: peer.PreSharedKey,
				AllowedIPs:   peer.AllowedIps,
			},
		}
		s.peers.Store(peer.PublicKey, mu)
		s.peerCount.Add(1)
		for _, cidr := range peer.AllowedIps {
			if addr, err := parseFirstAddr(cidr); err == nil {
				s.peersByIP.Store(addr, mu)
			}
		}
	}

	return s, nil
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

	// Tag the session with the peer's user identity when the tunnel source IP
	// maps to a known peer. This makes the user visible in access logs and
	// enables per-user traffic accounting via the stats manager.
	if addrPort, err := netip.ParseAddrPort(conn.RemoteAddr().String()); err == nil {
		if v, ok := s.peersByIP.Load(addrPort.Addr()); ok {
			inbound.User = v.(*protocol.MemoryUser)
		}
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

// ipc returns the wgIpcSetter used by AddUser / RemoveUser.
// In production this is s.dev (set after Start). Tests inject via ipcOverride.
// Callers must NOT hold s.mu.
func (s *Server) ipc() (wgIpcSetter, error) {
	if s.ipcOverride != nil {
		return s.ipcOverride, nil
	}
	s.mu.Lock()
	dev := s.dev
	s.mu.Unlock()
	if dev == nil {
		return nil, errors.New("wireguard server is not running")
	}
	return dev, nil
}

// AddUser implements proxy.UserManager.
// The peer is installed into the running WireGuard device via IPC and
// tracked in the in-memory maps so that subsequent API calls and log
// annotations see it immediately.
func (s *Server) AddUser(_ context.Context, u *protocol.MemoryUser) error {
	account, ok := u.Account.(*MemoryAccount)
	if !ok {
		return errors.New("not a WireGuard account")
	}
	ipc, err := s.ipc()
	if err != nil {
		return err
	}
	if err := ipc.IpcSet(buildPeerIPC(account)); err != nil {
		return err
	}
	email := u.Email
	if email == "" {
		email = account.PublicKey
	}
	u.Email = email
	if _, loaded := s.peers.LoadOrStore(email, u); loaded {
		return errors.New("peer ", email, " already exists")
	}
	s.peerCount.Add(1)
	for _, cidr := range account.AllowedIPs {
		if addr, err := parseFirstAddr(cidr); err == nil {
			s.peersByIP.Store(addr, u)
		}
	}
	return nil
}

// RemoveUser implements proxy.UserManager.
func (s *Server) RemoveUser(_ context.Context, email string) error {
	v, ok := s.peers.LoadAndDelete(email)
	if !ok {
		return errors.New("peer ", email, " not found")
	}
	s.peerCount.Add(-1)
	mu := v.(*protocol.MemoryUser)
	account := mu.Account.(*MemoryAccount)
	for _, cidr := range account.AllowedIPs {
		if addr, err := parseFirstAddr(cidr); err == nil {
			s.peersByIP.Delete(addr)
		}
	}
	ipc, err := s.ipc()
	if err != nil {
		return err
	}
	return ipc.IpcSet(buildRemovePeerIPC(account.PublicKey))
}

// GetUser implements proxy.UserManager.
func (s *Server) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	v, ok := s.peers.Load(email)
	if !ok {
		return nil
	}
	return v.(*protocol.MemoryUser)
}

// GetUsers implements proxy.UserManager.
func (s *Server) GetUsers(_ context.Context) []*protocol.MemoryUser {
	var out []*protocol.MemoryUser
	s.peers.Range(func(_, v any) bool {
		out = append(out, v.(*protocol.MemoryUser))
		return true
	})
	return out
}

// GetUsersCount implements proxy.UserManager.
func (s *Server) GetUsersCount(_ context.Context) int64 {
	return s.peerCount.Load()
}
