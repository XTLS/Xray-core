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

// udpConnEntry holds state for a UDP connection keyed by source 2-tuple (FullCone NAT)
type udpConnEntry struct {
	lastActive int64
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
	cone          bool
	udpConns      map[net.Destination]*udpConnEntry
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
	for src, conn := range t.udpConns {
		if time.Now().Unix()-atomic.LoadInt64(&conn.lastActive) > 300 {
			conn.cancel()
			delete(t.udpConns, src)
			// Tolerant cleanup - don't panic on close errors
			if err := conn.done.Close(); err != nil {
				errors.LogDebug(t.ctx, "failed to close done instance: ", err)
			}
			if err := common.Close(conn.writer); err != nil {
				errors.LogDebug(t.ctx, "failed to close writer: ", err)
			}
		}
	}
	return nil
}

func (t *Handler) HandleUDPPacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer, ipStack *stack.Stack) {
	src, dest := net.UDPDestination(net.IPAddress(id.RemoteAddress.AsSlice()), net.Port(id.RemotePort)), net.UDPDestination(net.IPAddress(id.LocalAddress.AsSlice()), net.Port(id.LocalPort))
	if data := pkt.Data().AsRange().ToSlice(); len(data) > 0 {
		t.Lock()
		conn, found := t.udpConns[src]
		if !found {
			reader, writer := pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(16*1024))
			// Create cancel function BEFORE spawning goroutine to avoid race condition
			ctx, cancel := context.WithCancel(context.WithValue(t.ctx, "cone", t.cone))
			conn = &udpConnEntry{reader: reader, writer: writer, done: done.New(), cancel: cancel}
			t.udpConns[src] = conn
			if t.udpChecker != nil && len(t.udpConns) == 1 {
				common.Must(t.udpChecker.Start())
			}
			t.Unlock()
			go func() {
				defer func() {
					cancel()
					t.Lock()
					delete(t.udpConns, src)
					t.Unlock()
					// Tolerant cleanup - don't panic on close errors
					if err := conn.done.Close(); err != nil {
						errors.LogDebug(ctx, "failed to close done instance: ", err)
					}
					if err := common.Close(conn.writer); err != nil {
						errors.LogDebug(ctx, "failed to close writer: ", err)
					}
				}()
				t.dispatcher.DispatchLink(c.ContextWithID(session.ContextWithInbound(ctx, &session.Inbound{Name: "tun", Source: src, User: &protocol.MemoryUser{Level: t.config.UserLevel}}), session.NewID()), dest, &transport.Link{Reader: conn.reader, Writer: &udpWriter{ctx: ctx, stack: ipStack, src: dest, dest: src}})
			}()
		} else {
			atomic.StoreInt64(&conn.lastActive, time.Now().Unix())
			t.Unlock()
		}
		b := buf.New()
		b.Write(data)
		b.UDP = &dest
		conn.writer.WriteMultiBuffer(buf.MultiBuffer{b})
	}
}

type udpWriter struct {
	ctx   context.Context
	stack *stack.Stack
	src   net.Destination
	dest  net.Destination
}

func (w *udpWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, b := range mb {
		if b.UDP != nil {
			w.src = *b.UDP
		}
		netProto := header.IPv4ProtocolNumber
		if !w.src.Address.Family().IsIPv4() {
			netProto = header.IPv6ProtocolNumber
		}
		route, err := w.stack.FindRoute(defaultNIC, tcpip.AddrFromSlice(w.src.Address.IP()), tcpip.AddrFromSlice(w.dest.Address.IP()), netProto, false)
		if err != nil {
			errors.LogDebug(w.ctx, "UDP route not found for ", w.src, " -> ", w.dest, ": ", err)
			b.Release()
			continue
		}
		// Use defer-style cleanup with anonymous function to ensure resources are released
		func() {
			defer route.Release()
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: header.UDPMinimumSize, Payload: buffer.MakeWithData(b.Bytes())})
			defer pkt.DecRef()
			udpHdr := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
			udpHdr.Encode(&header.UDPFields{SrcPort: uint16(w.src.Port), DstPort: uint16(w.dest.Port), Length: uint16(pkt.Size())})
			udpHdr.SetChecksum(^udpHdr.CalculateChecksum(checksum.Checksum(b.Bytes(), route.PseudoHeaderChecksum(header.UDPProtocolNumber, uint16(pkt.Size())))))
			route.WritePacket(stack.NetworkHeaderParams{Protocol: header.UDPProtocolNumber, TTL: 64}, pkt)
		}()
		b.Release()
	}
	return nil
}

// Init the Handler instance with necessary parameters
func (t *Handler) Init(ctx context.Context, pm policy.Manager, dispatcher routing.Dispatcher) error {
	// Safe type assertion with default to true for FullCone behavior
	if cone, ok := ctx.Value("cone").(bool); ok {
		t.cone = cone
	} else {
		t.cone = true
	}
	t.ctx, t.policyManager, t.dispatcher = core.ToBackgroundDetachedContext(ctx), pm, dispatcher
	t.udpConns = make(map[net.Destination]*udpConnEntry)
	t.udpChecker = &task.Periodic{Interval: time.Minute, Execute: t.cleanupUDP}
	tunInterface, err := NewTun(TunOptions{Name: t.config.Name, MTU: t.config.MTU})
	if err != nil {
		return err
	}
	errors.LogInfo(t.ctx, t.config.Name, " created")
	tunStack, err := NewStack(t.ctx, StackOptions{Tun: tunInterface, IdleTimeout: pm.ForLevel(t.config.UserLevel).Timeouts.ConnectionIdle}, t)
	if err != nil {
		_ = tunInterface.Close()
		return err
	}
	if err = tunStack.Start(); err != nil {
		_ = tunStack.Close()
		_ = tunInterface.Close()
		return err
	}
	if err = tunInterface.Start(); err != nil {
		_ = tunStack.Close()
		_ = tunInterface.Close()
		return err
	}
	t.stack = tunStack
	errors.LogInfo(t.ctx, t.config.Name, " up")
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
