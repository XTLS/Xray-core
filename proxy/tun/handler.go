package tun

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Handler is managing object that tie together tun interface, ip stack and dispatch connections to the routing
type Handler struct {
	ctx           context.Context
	config        *Config
	stack         Stack
	policyManager policy.Manager
	dispatcher    routing.Dispatcher
}

// ConnectionHandler interface with the only method that stack is going to push new connections to
type ConnectionHandler interface {
	HandleConnection(conn net.Conn, destination net.Destination)
}

// Handler implements ConnectionHandler
var _ ConnectionHandler = (*Handler)(nil)

func (t *Handler) policy() policy.Session {
	p := t.policyManager.ForLevel(t.config.UserLevel)
	return p
}

// Init the Handler instance with necessary parameters
func (t *Handler) Init(ctx context.Context, pm policy.Manager, dispatcher routing.Dispatcher) error {
	var err error

	t.ctx = core.ToBackgroundDetachedContext(ctx)
	t.policyManager = pm
	t.dispatcher = dispatcher

	tunName := t.config.Name
	tunOptions := TunOptions{
		Name: tunName,
		MTU:  t.config.MTU,
	}
	tunInterface, err := NewTun(tunOptions)
	if err != nil {
		return err
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

	errors.LogInfo(t.ctx, tunName, " up")
	return nil
}

// HandleConnection pass the connection coming from the ip stack to the routing dispatcher
func (t *Handler) HandleConnection(conn net.Conn, destination net.Destination) {
	sid := session.NewID()
	ctx := c.ContextWithID(t.ctx, sid)
	errors.LogInfo(ctx, "processing connection from: ", conn.RemoteAddr())

	inbound := session.Inbound{}
	inbound.Name = "tun"
	inbound.CanSpliceCopy = 1
	inbound.Source = net.DestinationFromAddr(conn.RemoteAddr())
	inbound.User = &protocol.MemoryUser{
		Level: t.config.UserLevel,
	}

	ctx = session.ContextWithInbound(ctx, &inbound)
	ctx = session.SubContextFromMuxInbound(ctx)

	link, err := t.dispatcher.Dispatch(ctx, destination)
	if err != nil {
		errors.LogError(ctx, errors.New("connection failed").Base(err))
		_ = conn.Close()
		return
	}

	timer := &deadlineTimer{conn: conn, timeouts: t.policy().Timeouts}
	requestFunc := func() error {
		return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
	}
	responseFunc := func() error {
		return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
	}
	responseDonePost := task.OnSuccess(responseFunc, task.Close(link.Writer))
	if err := task.Run(ctx, requestFunc, responseDonePost); err != nil {
		_ = common.Interrupt(link.Reader)
		_ = common.Interrupt(link.Writer)
		errors.LogInfo(ctx, errors.New("connection closed").Base(err))
		return
	}

	errors.LogInfo(ctx, "connection completed")
}

type deadlineTimer struct {
	conn     net.Conn
	timeouts policy.Timeout
}

func (a *deadlineTimer) Update() {
	a.conn.SetDeadline(time.Now().Add(a.timeouts.ConnectionIdle))
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
