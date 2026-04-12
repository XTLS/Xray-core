package tun

import (
	"context"
	"syscall"

	"github.com/xtls/xray-core/common"
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
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Handler is managing object that tie together tun interface, ip stack and dispatch connections to the routing
type Handler struct {
	ctx             context.Context
	config          *Config
	stack           Stack
	tun             Tun
	policyManager   policy.Manager
	dispatcher      routing.Dispatcher
	tag             string
	sniffingRequest session.SniffingRequest
}

// ConnectionHandler interface with the only method that stack is going to push new connections to
type ConnectionHandler interface {
	HandleConnection(conn net.Conn, destination net.Destination)
}

// Handler implements ConnectionHandler
var _ ConnectionHandler = (*Handler)(nil)

// Init the Handler instance with necessary parameters
func (t *Handler) Init(ctx context.Context, pm policy.Manager, dispatcher routing.Dispatcher) error {
	var err error

	// Retrieve tag and sniffing config from context (set by AlwaysOnInboundHandler)
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		t.tag = inbound.Tag
	}
	if content := session.ContentFromContext(ctx); content != nil {
		t.sniffingRequest = content.SniffingRequest
	}

	t.ctx = core.ToBackgroundDetachedContext(ctx)
	t.policyManager = pm
	t.dispatcher = dispatcher

	tunName := t.config.Name
	tunInterface, err := NewTun(t.config)
	if err != nil {
		return err
	}

	if t.config.AutoOutboundsInterface != "" {
		tunIndex, err := tunInterface.Index()
		if err != nil {
			_ = tunInterface.Close()
			return err
		}
		if t.config.AutoOutboundsInterface == "auto" {
			t.config.AutoOutboundsInterface = ""
		}
		updater = &InterfaceUpdater{tunIndex: tunIndex, fixedName: t.config.AutoOutboundsInterface}
		updater.Update()
		internet.RegisterDialerController(func(network, address string, c syscall.RawConn) error {
			iface := updater.Get()
			if iface == nil {
				errors.LogInfo(context.Background(), "[tun] falied to set interface > iface == nil")
				return nil
			}
			return c.Control(func(fd uintptr) {
				err := setinterface(network, address, fd, iface)
				if err != nil {
					errors.LogInfoInner(context.Background(), err, "[tun] falied to set interface")
				}
			})
		})
	}

	errors.LogInfo(t.ctx, tunName, " created")

	tunStackOptions := StackOptions{
		Tun:         tunInterface,
		IdleTimeout: pm.ForLevel(t.config.UserLevel).Timeouts.ConnectionIdle,
	}
	tunStack, err := NewStack(t.ctx, tunStackOptions, t)
	if err != nil {
		_ = tunInterface.Close()
		return err
	}

	err = tunStack.Start()
	if err != nil {
		_ = tunStack.Close()
		_ = tunInterface.Close()
		return err
	}

	err = tunInterface.Start()
	if err != nil {
		_ = tunStack.Close()
		_ = tunInterface.Close()
		return err
	}

	t.stack = tunStack
	t.tun = tunInterface

	errors.LogInfo(t.ctx, tunName, " up")
	return nil
}

// HandleConnection pass the connection coming from the ip stack to the routing dispatcher
func (t *Handler) HandleConnection(conn net.Conn, destination net.Destination) {
	// when handling is done with any outcome, always signal back to the incoming connection
	// to close, send completion packets back to the network, and cleanup
	defer conn.Close()

	ctx, cancel := context.WithCancel(t.ctx)
	defer cancel()
	ctx = c.ContextWithID(ctx, session.NewID())

	source := net.DestinationFromAddr(conn.RemoteAddr())
	inbound := session.Inbound{
		Name:          "tun",
		Tag:           t.tag,
		CanSpliceCopy: 3,
		Source:        source,
		User: &protocol.MemoryUser{
			Level: t.config.UserLevel,
		},
	}

	ctx = session.ContextWithInbound(ctx, &inbound)
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: t.sniffingRequest,
	})
	ctx = session.SubContextFromMuxInbound(ctx)

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   inbound.Source,
		To:     destination,
		Status: log.AccessAccepted,
		Reason: "",
	})
	errors.LogInfo(ctx, "processing from ", source, " to ", destination)

	link := &transport.Link{
		Reader: &buf.TimeoutWrapperReader{Reader: buf.NewReader(conn)},
		Writer: buf.NewWriter(conn),
	}
	if err := t.dispatcher.DispatchLink(ctx, destination, link); err != nil {
		errors.LogError(ctx, errors.New("connection closed").Base(err))
	}
}

// Close implements common.Closable.
func (t *Handler) Close() error {
	return errors.Combine(t.stack.Close(), t.tun.Close())
}

// Network implements proxy.Inbound
// and exists only to comply to proxy interface, declaring it doesn't listen on any network,
// making the process not open any port for this inbound (input will be network interface)
func (t *Handler) Network() []net.Network {
	return []net.Network{}
}

// Process implements proxy.Inbound
// and exists only to comply to proxy interface, which should never get any inputs due to no listening ports
func (t *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		t := &Handler{config: config.(*Config)}
		err := core.RequireFeatures(ctx, func(pm policy.Manager, dispatcher routing.Dispatcher) error {
			return t.Init(ctx, pm, dispatcher)
		})
		return t, err
	}))
}
