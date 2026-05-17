package mieru

import (
	"context"
	"fmt"
	stdnet "net"
	"strconv"
	"sync"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/model"
	mieruserver "github.com/enfein/mieru/v3/apis/server"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	xprotocol "github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/mieru/account"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Server is the inbound handler for the mieru protocol.
//
// Lifecycle:
//   - NewServer prepares the mieru server with a custom stream listener factory
//     (the connFeeder) that hands xray-accepted connections to mieru.
//   - The first Process call lazily starts mieru and the accept-loop goroutine.
//   - Each Process pushes the raw conn into the feeder, then blocks until mieru
//     finishes reading from it. Mieru's accept loop runs in the background,
//     dispatching each accepted session to xray's router.
type Server struct {
	config        *ServerConfig
	validator     *account.Validator
	policyManager policy.Manager

	startOnce sync.Once
	startErr  error
	mieru     mieruserver.Server
	feeder    *connFeeder

	dispatcherSlot atomicDispatcher
	// inboundTag, gateway and source need to be carried into the per-session
	// dispatch context because mieru's accept loop runs detached from the
	// per-Process ctx. We latch them on the first Process call.
	inboundTag string
	gateway    net.Destination
	tagOnce    sync.Once
}

// NewServer creates a new mieru inbound server.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	if len(config.Users) == 0 {
		return nil, errors.New("mieru inbound requires at least one user")
	}
	v := core.MustFromContext(ctx)
	validator := account.NewValidator()

	pbUsers := make([]*appctlpb.User, 0, len(config.Users))
	for _, user := range config.Users {
		mu, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to get mieru user").Base(err)
		}
		if err := validator.Add(mu); err != nil {
			return nil, errors.New("failed to add user").Base(err)
		}
		acc, ok := mu.Account.(*account.MemoryAccount)
		if !ok {
			return nil, errors.New("invalid mieru account type")
		}
		pbUsers = append(pbUsers, &appctlpb.User{
			Name:     proto.String(acc.Username),
			Password: proto.String(acc.Password),
		})
	}

	feeder := newConnFeeder()
	srvCfg := &appctlpb.ServerConfig{
		Users: pbUsers,
		// PortBindings is mandatory in mieru's validator. We set a placeholder;
		// the real listening socket comes from xray's inbound, and we install a
		// listener factory (the feeder) that emits xray-provided connections.
		PortBindings: []*appctlpb.PortBinding{
			{
				Port:     proto.Int32(1),
				Protocol: appctlpb.TransportProtocol_TCP.Enum(),
			},
		},
		AdvancedSettings: &appctlpb.ServerAdvancedSettings{
			UserHintIsMandatory: proto.Bool(config.UserHintIsMandatory),
		},
	}
	if config.Mtu > 0 {
		srvCfg.Mtu = proto.Int32(config.Mtu)
	}

	ms := mieruserver.NewServer()
	if err := ms.Store(&mieruserver.ServerConfig{
		Config:                srvCfg,
		StreamListenerFactory: feeder,
	}); err != nil {
		return nil, errors.New("failed to store mieru server config").Base(err)
	}

	return &Server{
		config:        config,
		validator:     validator,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		mieru:         ms,
		feeder:        feeder,
	}, nil
}

// Network implements proxy.Inbound. The mieru framing rides over a TCP stream
// from xray's perspective; the upstream UDP transport is initiated by clients
// against UDP inbounds, which is not handled here.
func (s *Server) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

// Process implements proxy.Inbound.
func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inbound.Name = "mieru"
		inbound.CanSpliceCopy = 3
		inbound.User = &xprotocol.MemoryUser{}
		s.tagOnce.Do(func() {
			s.inboundTag = inbound.Tag
			s.gateway = inbound.Gateway
		})
	}

	s.dispatcherSlot.Store(dispatcher)

	if err := s.ensureStarted(ctx); err != nil {
		return err
	}

	// Push the live conn into mieru's accept pipeline. mieru's event loop reads
	// from the conn; we block until it closes the wrapper, which happens when
	// mieru's underlay processing returns (typically on EOF or session
	// termination).
	tracker := newTrackedConn(conn)
	if err := s.feeder.Push(ctx, tracker); err != nil {
		return errors.New("failed to push mieru connection").Base(err)
	}
	<-tracker.Done()
	return nil
}

func (s *Server) ensureStarted(ctx context.Context) error {
	s.startOnce.Do(func() {
		if err := s.mieru.Start(); err != nil {
			s.startErr = errors.New("failed to start mieru server").Base(err)
			return
		}
		// Detach from the per-request ctx but keep the xray core instance so the
		// dispatch goroutine can rebuild a usable context for the router.
		loopCtx := core.ToBackgroundDetachedContext(ctx)
		go s.acceptLoop(loopCtx)
	})
	return s.startErr
}

func (s *Server) acceptLoop(loopCtx context.Context) {
	for {
		proxyConn, req, err := s.mieru.Accept()
		if err != nil {
			errors.LogInfo(loopCtx, "mieru accept loop ended: ", err)
			return
		}
		go s.dispatch(loopCtx, proxyConn, req)
	}
}

func (s *Server) dispatch(ctx context.Context, proxyConn stdnet.Conn, req *model.Request) {
	defer proxyConn.Close()

	dispatcher := s.dispatcherSlot.Load()
	if dispatcher == nil {
		errors.LogWarning(ctx, "mieru: dispatcher is not set, dropping session")
		return
	}

	user := &xprotocol.MemoryUser{}
	if userCtx, ok := proxyConn.(apicommon.UserContext); ok && userCtx.UserName() != "" {
		if u := s.validator.Get(userCtx.UserName()); u != nil {
			user = u
		}
	}

	// Attach an xray Inbound to the dispatch context so the router sees the
	// inbound tag and user. ctx already carries the xray core instance (see
	// ensureStarted); we re-populate the Inbound from values latched on the
	// first Process call.
	dispatchCtx := session.ContextWithInbound(ctx, &session.Inbound{
		Name:          "mieru",
		Tag:           s.inboundTag,
		Gateway:       s.gateway,
		User:          user,
		CanSpliceCopy: 3,
	})

	dest, isUDP, err := requestToDestination(req)
	if err != nil {
		errors.LogWarning(dispatchCtx, "invalid mieru request: ", err)
		return
	}

	bindAddr := model.AddrSpec{IP: stdnet.IPv4zero, Port: 0}
	resp := &model.Response{Reply: constant.Socks5ReplySuccess, BindAddr: bindAddr}
	if err := resp.WriteToSocks5(proxyConn); err != nil {
		errors.LogWarning(dispatchCtx, "failed to write mieru socks5 response: ", err)
		return
	}

	dispatchCtx = log.ContextWithAccessMessage(dispatchCtx, &log.AccessMessage{
		To:     dest,
		Status: log.AccessAccepted,
		Email:  user.Email,
	})

	if isUDP {
		// For UDP-Associate, mieru tunnels packets over the stream as
		// length-prefixed frames. The framed stream is forwarded to dest like a
		// TCP stream; the inner UDP semantics are visible only to the client.
		errors.LogInfo(dispatchCtx, "tunneling mieru UDP-associate stream to ", dest)
	} else {
		errors.LogInfo(dispatchCtx, "tunneling mieru stream to ", dest)
	}

	if err := dispatcher.DispatchLink(dispatchCtx, dest, &transport.Link{
		Reader: buf.NewReader(proxyConn),
		Writer: buf.NewWriter(proxyConn),
	}); err != nil {
		errors.LogWarning(dispatchCtx, "mieru dispatch failed: ", err)
	}
}

// AddUser, RemoveUser, GetUser, GetUsers, GetUsersCount expose mieru user
// management to the xray API plane.
func (s *Server) AddUser(_ context.Context, u *xprotocol.MemoryUser) error {
	return s.validator.Add(u)
}

func (s *Server) RemoveUser(_ context.Context, email string) error {
	return s.validator.Del(email)
}

func (s *Server) GetUser(_ context.Context, email string) *xprotocol.MemoryUser {
	return s.validator.GetByEmail(email)
}

func (s *Server) GetUsers(_ context.Context) []*xprotocol.MemoryUser {
	return s.validator.GetAll()
}

func (s *Server) GetUsersCount(_ context.Context) int64 {
	return s.validator.GetCount()
}

func requestToDestination(req *model.Request) (net.Destination, bool, error) {
	if req == nil {
		return net.Destination{}, false, fmt.Errorf("request is nil")
	}
	netStr := "tcp"
	isUDP := false
	switch req.Command {
	case constant.Socks5ConnectCmd:
		netStr = "tcp"
	case constant.Socks5UDPAssociateCmd:
		netStr = "udp"
		isUDP = true
	default:
		return net.Destination{}, false, fmt.Errorf("unsupported socks5 command: %d", req.Command)
	}
	host := req.DstAddr.FQDN
	if host == "" && len(req.DstAddr.IP) > 0 {
		host = req.DstAddr.IP.String()
	}
	if host == "" {
		return net.Destination{}, false, fmt.Errorf("empty destination address")
	}
	dest, err := net.ParseDestination(netStr + ":" + stdnet.JoinHostPort(host, strconv.Itoa(req.DstAddr.Port)))
	if err != nil {
		return net.Destination{}, false, err
	}
	return dest, isUDP, nil
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
