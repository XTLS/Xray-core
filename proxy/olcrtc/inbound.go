package olcrtc

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/bridge"
	"github.com/xtls/xray-core/transport"
)

// Server is the olcrtc inbound handler. It is self-driven: rather than binding a
// socket, it joins the configured room, accepts tunnel streams, and dispatches
// each CONNECT target through Xray's router. It implements proxy.SelfDrivenInbound.
type Server struct {
	config     *ServerConfig
	tag        string
	dispatcher routing.Dispatcher
}

// NewServer creates an olcrtc inbound handler from config. It captures the
// inbound tag from ctx (set by the handler manager) and resolves the router.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	s := &Server{config: config}
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
// accepted tunnel stream's target is dispatched through Xray's router; the
// resulting link is piped against the stream.
func (s *Server) Serve(ctx context.Context) error {
	dial := func(dctx context.Context, addr string, port int) (net.Conn, error) {
		return s.dispatch(dctx, addr, port)
	}
	if err := bridge.RunServer(ctx, serverBridgeConfig(s.config), dial); err != nil {
		return errors.New("olcrtc inbound ended").Base(err)
	}
	return nil
}

// dispatch routes a single tunnel target through Xray and returns a net.Conn
// whose Read side is the target's downlink and whose Write side is its uplink.
func (s *Server) dispatch(ctx context.Context, addr string, port int) (net.Conn, error) {
	dest := net.TCPDestination(net.ParseAddress(addr), net.Port(port))

	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Tag:    s.tag,
		Source: net.TCPDestination(net.AnyIP, 0),
	})
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

// linkCloser tears down a dispatched link when the tunnel conn is closed.
type linkCloser struct {
	link *transport.Link
}

func (l *linkCloser) Close() error {
	common.Interrupt(l.link.Reader)
	common.Close(l.link.Writer)
	return nil
}
