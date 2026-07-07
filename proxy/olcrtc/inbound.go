package olcrtc

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/bridge"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Server is the olcrtc inbound handler. It is self-driven: rather than binding a
// socket, it joins the configured room, accepts tunnel streams, and dispatches
// each CONNECT target through Xray's router. It implements proxy.SelfDrivenInbound.
//
// It also implements proxy.UserManager (backed by [Validator]) so users can be
// added/removed at runtime via HandlerService (AlterInbound), and proxy.Inbound
// (with stub methods) so the command service can reach that UserManager.
type Server struct {
	config     *ServerConfig
	tag        string
	dispatcher routing.Dispatcher
	validator  *Validator
}

// NewServer creates an olcrtc inbound handler from config. It captures the
// inbound tag from ctx (set by the handler manager) and resolves the router.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	s := &Server{config: config, validator: NewValidator()}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		s.tag = inbound.Tag
	}
	if err := core.RequireFeatures(ctx, func(d routing.Dispatcher) error {
		s.dispatcher = d
		return nil
	}); err != nil {
		return nil, err
	}
	return s, nil
}

// Serve brings up the server carrier and blocks until ctx is cancelled. Each
// accepted tunnel stream is authenticated by authHook and its target dispatched
// through Xray's router; the resulting link is piped against the stream.
func (s *Server) Serve(ctx context.Context) error {
	dial := func(dctx context.Context, addr string, port int, sessionID string) (net.Conn, error) {
		return s.dispatch(dctx, addr, port, sessionID)
	}
	cfg := serverBridgeConfig(s.config)
	cfg.AuthHook = s.authHook
	if err := bridge.RunServer(ctx, cfg, dial); err != nil {
		return errors.New("olcrtc inbound ended").Base(err)
	}
	return nil
}

// authHook authenticates a client handshake. The client presents its identity as
// the handshake device token (the outbound's deviceId). When no users are
// registered the inbound runs in "open mode" — the shared room key is the only
// gate. Once users exist, the token must match a registered user or the
// handshake is rejected. On success it returns a sessionID that encodes the
// resolved user so dispatch can attach it without shared state.
func (s *Server) authHook(deviceID string, _ map[string]any) (string, error) {
	if s.validator.Empty() {
		return encodeSessionID("", 0), nil
	}
	u := s.validator.Get(deviceID)
	if u == nil {
		// Reason is forwarded to the client verbatim; keep it non-specific.
		return "", errors.New("unauthorized")
	}
	return encodeSessionID(u.Email, u.Level), nil
}

// dispatch routes a single tunnel target through Xray and returns a net.Conn
// whose Read side is the target's downlink and whose Write side is its uplink.
// The authenticated user (decoded from sessionID) is attached to the inbound
// session so routing, per-user stats, online tracking and speed limits apply.
func (s *Server) dispatch(ctx context.Context, addr string, port int, sessionID string) (net.Conn, error) {
	dest := net.TCPDestination(net.ParseAddress(addr), net.Port(port))

	inb := &session.Inbound{
		Tag:    s.tag,
		Source: net.TCPDestination(net.AnyIP, 0),
	}
	if email, level := decodeSessionID(sessionID); email != "" {
		// Attaching the user makes the dispatcher key per-user traffic stats,
		// online tracking and the speed limit by email — across every device.
		// Online tracking counters are themselves per-email, so Source stays a
		// plain IP (routing may inspect it); per-device granularity is a planned
		// follow-up tied to per-user secrets.
		inb.User = &protocol.MemoryUser{Email: email, Level: level}
	}
	ctx = session.ContextWithInbound(ctx, inb)
	ctx = session.ContextWithContent(ctx, new(session.Content))

	errors.LogInfo(ctx, "olcrtc: dispatching tunnel target ", dest)
	link, err := s.dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return nil, errors.New("olcrtc: dispatch ", dest, " failed").Base(err)
	}

	return cnc.NewConnection(
		cnc.ConnectionInputMulti(link.Writer),
		cnc.ConnectionOutputMulti(link.Reader),
		cnc.ConnectionOnClose(&linkCloser{link: link}),
	), nil
}

// --- proxy.Inbound (stub) --------------------------------------------------
//
// olcrtc has no socket listener, so these satisfy proxy.Inbound only so the
// command service (AlterInbound) can reach the proxy.UserManager below via
// SelfDrivenInboundHandler.GetInbound(). Process is never invoked.

// Network implements proxy.Inbound.
func (s *Server) Network() []net.Network { return []net.Network{net.Network_TCP} }

// Process implements proxy.Inbound. It is never called for a self-driven inbound.
func (s *Server) Process(context.Context, net.Network, stat.Connection, routing.Dispatcher) error {
	return errors.New("olcrtc inbound is self-driven and has no socket listener")
}

// --- proxy.UserManager -----------------------------------------------------

// AddUser implements proxy.UserManager.
func (s *Server) AddUser(_ context.Context, u *protocol.MemoryUser) error {
	return s.validator.Add(u)
}

// RemoveUser implements proxy.UserManager.
func (s *Server) RemoveUser(_ context.Context, email string) error {
	return s.validator.Del(email)
}

// GetUser implements proxy.UserManager.
func (s *Server) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	return s.validator.GetByEmail(email)
}

// GetUsers implements proxy.UserManager.
func (s *Server) GetUsers(_ context.Context) []*protocol.MemoryUser {
	return s.validator.GetAll()
}

// GetUsersCount implements proxy.UserManager.
func (s *Server) GetUsersCount(_ context.Context) int64 {
	return s.validator.GetCount()
}

// --- sessionID codec -------------------------------------------------------
//
// The vendored server hands the AuthHook-returned sessionID to the dial hook for
// every tunnel stream of a connection. We use it as a stateless carrier for the
// authenticated identity: "u1:<base64url(email)>:<level>:<uuid>". The trailing
// uuid keeps each connection's sessionID unique (the server tracks peers by it),
// while the prefix lets dispatch recover the user with no shared map.

const sessionUserPrefix = "u1:"

func encodeSessionID(email string, level uint32) string {
	id := uuid.New()
	if email == "" {
		return "anon:" + id.String()
	}
	return sessionUserPrefix +
		base64.RawURLEncoding.EncodeToString([]byte(email)) + ":" +
		strconv.FormatUint(uint64(level), 10) + ":" + id.String()
}

func decodeSessionID(sid string) (email string, level uint32) {
	if !strings.HasPrefix(sid, sessionUserPrefix) {
		return "", 0
	}
	parts := strings.SplitN(strings.TrimPrefix(sid, sessionUserPrefix), ":", 3)
	if len(parts) != 3 {
		return "", 0
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", 0
	}
	lvl, _ := strconv.ParseUint(parts[1], 10, 32)
	return string(raw), uint32(lvl)
}

// linkCloser tears down a dispatched link when the tunnel conn is closed.
type linkCloser struct {
	link *transport.Link
}

func (l *linkCloser) Close() error {
	common.Interrupt(l.link.Reader)
	common.Close(l.link.Writer)
	return nil
}
