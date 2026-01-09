package tun

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type udpConn struct {
	lastActive atomic.Int64
	reader     buf.Reader
	writer     buf.Writer
	done       *done.Instance
	cancel     context.CancelFunc
}

// Handler is managing object that tie together tun interface, ip stack and dispatch connections to the routing
type Handler struct {
	sync.Mutex
	ctx           context.Context
	config        *Config
	stack         Stack
	policyManager policy.Manager
	dispatcher    routing.Dispatcher
	udpConns      map[net.Destination]*udpConn
	udpChecker    *task.Periodic
}

// ConnectionHandler interface with the only method that stack is going to push new connections to
type ConnectionHandler interface {
	HandleConnection(conn net.Conn, destination net.Destination)
}

// Handler implements ConnectionHandler
var _ ConnectionHandler = (*Handler)(nil)

func (t *Handler) policy() policy.Session {
	return t.policyManager.ForLevel(t.config.UserLevel)
}

func (t *Handler) cleanupUDP() error {
	t.Lock()
	defer t.Unlock()
	if len(t.udpConns) == 0 {
		return errors.New("no connections")
	}
	now := time.Now().Unix()
	for src, conn := range t.udpConns {
		if now-conn.lastActive.Load() > 300 {
			conn.cancel()
			common.Must(conn.done.Close())
			common.Must(common.Close(conn.writer))
			delete(t.udpConns, src)
		}
	}
	return nil
}

func (t *Handler) HandleUDPPacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer, ipStack *stack.Stack) {
	src := net.UDPDestination(net.IPAddress(id.RemoteAddress.AsSlice()), net.Port(id.RemotePort))
	dest := net.UDPDestination(net.IPAddress(id.LocalAddress.AsSlice()), net.Port(id.LocalPort))
	data := pkt.Data().AsRange().ToSlice()
	if len(data) == 0 {
		return
	}

	t.Lock()
	conn, found := t.udpConns[src]
	if !found {
		reader, writer := pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(16*1024))
		conn = &udpConn{reader: reader, writer: writer, done: done.New()}
		t.udpConns[src] = conn
		if t.udpChecker != nil && len(t.udpConns) == 1 {
			common.Must(t.udpChecker.Start())
		}
		t.Unlock()

		go func() {
			ctx, cancel := context.WithCancel(t.ctx)
			conn.cancel = cancel
			defer func() {
				cancel()
				t.Lock()
				delete(t.udpConns, src)
				t.Unlock()
				common.Must(conn.done.Close())
				common.Must(common.Close(conn.writer))
			}()

			inbound := &session.Inbound{
				Name:          "tun",
				Source:        src,
				CanSpliceCopy: 1,
				User:          &protocol.MemoryUser{Level: t.config.UserLevel},
			}
			ctx = session.ContextWithInbound(c.ContextWithID(ctx, session.NewID()), inbound)
			ctx = session.SubContextFromMuxInbound(ctx)
			link := &transport.Link{
				Reader: &buf.TimeoutWrapperReader{Reader: conn.reader},
				Writer: &udpWriter{stack: ipStack, src: dest, dest: src},
			}
			t.dispatcher.DispatchLink(ctx, dest, link)
		}()
	} else {
		conn.lastActive.Store(time.Now().Unix())
		t.Unlock()
	}

	b := buf.New()
	b.Write(data)
	b.UDP = &dest
	conn.writer.WriteMultiBuffer(buf.MultiBuffer{b})
}

type udpWriter struct {
	stack *stack.Stack
	src   net.Destination
	dest  net.Destination
}

func (w *udpWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, b := range mb {
		// Validate return packet address family matches expected destination
		if b.UDP != nil && b.UDP.Address.Family() != w.dest.Address.Family() {
			errors.LogWarning(context.Background(), "UDP return packet address family mismatch: expected ", w.dest.Address.Family(), ", got ", b.UDP.Address.Family())
			b.Release()
			continue
		}

		netProto := header.IPv4ProtocolNumber
		if !w.src.Address.Family().IsIPv4() {
			netProto = header.IPv6ProtocolNumber
		}

		route, err := w.stack.FindRoute(
			defaultNIC,
			tcpip.AddrFromSlice(w.src.Address.IP()),
			tcpip.AddrFromSlice(w.dest.Address.IP()),
			netProto,
			false,
		)
		if err != nil {
			b.Release()
			continue
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: header.UDPMinimumSize,
			Payload:            buffer.MakeWithData(b.Bytes()),
		})
		udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
		udp.Encode(&header.UDPFields{
			SrcPort: uint16(w.src.Port),
			DstPort: uint16(w.dest.Port),
			Length:  uint16(pkt.Size()),
		})
		xsum := route.PseudoHeaderChecksum(header.UDPProtocolNumber, uint16(pkt.Size()))
		udp.SetChecksum(^udp.CalculateChecksum(checksum.Checksum(b.Bytes(), xsum)))
		route.WritePacket(stack.NetworkHeaderParams{
			Protocol: header.UDPProtocolNumber,
			TTL:      64,
		}, pkt)
		pkt.DecRef()
		route.Release()
		b.Release()
	}
	return nil
}

// Init the Handler instance with necessary parameters
func (t *Handler) Init(ctx context.Context, pm policy.Manager, dispatcher routing.Dispatcher) error {
	var err error

	t.ctx = core.ToBackgroundDetachedContext(ctx)
	t.policyManager = pm
	t.dispatcher = dispatcher
	t.udpConns = make(map[net.Destination]*udpConn)
	t.udpChecker = &task.Periodic{Interval: time.Minute, Execute: t.cleanupUDP}

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

	link := &transport.Link{
		Reader: &buf.TimeoutWrapperReader{Reader: buf.NewReader(conn)},
		Writer: buf.NewWriter(conn),
	}
	if err := t.dispatcher.DispatchLink(ctx, destination, link); err != nil {
		errors.LogError(ctx, errors.New("connection closed").Base(err))
		return
	}

	errors.LogInfo(ctx, "connection completed")
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
