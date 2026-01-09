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

// udpConnID represents a UDP connection identifier
type udpConnID struct {
	src  net.Destination
	dest net.Destination
}

// udpConn represents a UDP connection for packet handling
type udpConn struct {
	lastActivityTime int64 // in seconds
	reader           buf.Reader
	writer           buf.Writer
	output           func([]byte, net.Destination) (int, error)
	remote           net.Addr
	local            net.Addr
	done             *done.Instance
	inactive         bool
	cancel           context.CancelFunc
}

func (c *udpConn) setInactive() {
	c.inactive = true
}

func (c *udpConn) updateActivity() {
	atomic.StoreInt64(&c.lastActivityTime, time.Now().Unix())
}

// ReadMultiBuffer implements buf.Reader
func (c *udpConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := c.reader.ReadMultiBuffer()
	if err != nil {
		return nil, err
	}
	c.updateActivity()
	return mb, nil
}

func (c *udpConn) Read(buf []byte) (int, error) {
	return 0, errors.New("Read not supported, use ReadMultiBuffer instead")
}

// Write implements io.Writer
func (c *udpConn) Write(data []byte) (int, error) {
	// Extract destination from the first buffer if available
	// For now, write with empty destination (will be filled by output function)
	n, err := c.output(data, net.Destination{})
	if err == nil {
		c.updateActivity()
	}
	return n, err
}

func (c *udpConn) Close() error {
	if c.cancel != nil {
		c.cancel()
	}
	common.Must(c.done.Close())
	common.Must(common.Close(c.writer))
	return nil
}

func (c *udpConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *udpConn) LocalAddr() net.Addr {
	return c.local
}

func (*udpConn) SetDeadline(time.Time) error {
	return nil
}

func (*udpConn) SetReadDeadline(time.Time) error {
	return nil
}

func (*udpConn) SetWriteDeadline(time.Time) error {
	return nil
}

// Handler is managing object that tie together tun interface, ip stack and dispatch connections to the routing
type Handler struct {
	sync.RWMutex
	
	ctx           context.Context
	config        *Config
	stack         Stack
	policyManager policy.Manager
	dispatcher    routing.Dispatcher
	cone          bool
	
	// UDP connection management
	udpConns   map[udpConnID]*udpConn
	udpChecker *task.Periodic
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

// getUDPConn gets or creates a UDP connection for the given source and destination
func (t *Handler) getUDPConn(source, dest net.Destination, ipStack *stack.Stack) (*udpConn, bool) {
	t.Lock()
	defer t.Unlock()
	
	id := udpConnID{
		src: source,
	}
	if !t.cone {
		id.dest = dest
	}
	
	if conn, found := t.udpConns[id]; found && !conn.done.Done() {
		conn.updateActivity()
		return conn, true
	}
	
	pReader, pWriter := pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(16*1024))
	conn := &udpConn{
		reader: pReader,
		writer: pWriter,
		output: func(data []byte, returnDest net.Destination) (int, error) {
			// Write UDP packet back to the stack with proper source address
			return t.writeUDPPacket(ipStack, data, returnDest, source)
		},
		remote: &net.UDPAddr{
			IP:   source.Address.IP(),
			Port: int(source.Port),
		},
		local: &net.UDPAddr{
			IP:   dest.Address.IP(),
			Port: int(dest.Port),
		},
		done: done.New(),
	}
	
	t.udpConns[id] = conn
	
	conn.updateActivity()
	return conn, false
}

// removeUDPConn removes a UDP connection
func (t *Handler) removeUDPConn(id udpConnID) {
	t.Lock()
	delete(t.udpConns, id)
	t.Unlock()
}

// cleanupUDPConns removes inactive UDP connections
func (t *Handler) cleanupUDPConns() error {
	nowSec := time.Now().Unix()
	t.Lock()
	defer t.Unlock()
	
	if len(t.udpConns) == 0 {
		return errors.New("UDP connection cleanup stopped: no active connections remaining")
	}
	
	for id, conn := range t.udpConns {
		if nowSec-atomic.LoadInt64(&conn.lastActivityTime) > 300 { // 5 minutes
			if !conn.inactive {
				conn.setInactive()
				conn.Close()
				delete(t.udpConns, id)
			}
		}
	}
	
	return nil
}

// writeUDPPacket writes a UDP packet back to the gVisor stack with custom source address
func (t *Handler) writeUDPPacket(ipStack *stack.Stack, data []byte, dest, source net.Destination) (int, error) {
	// Build UDP+IP packet with proper headers using gVisor's header builders
	
	// Determine IP version
	var ipHdrLen, udpHdrLen int
	isIPv4 := dest.Address.Family().IsIPv4()
	
	if isIPv4 {
		ipHdrLen = header.IPv4MinimumSize
	} else {
		ipHdrLen = header.IPv6MinimumSize
	}
	udpHdrLen = header.UDPMinimumSize
	
	totalLen := ipHdrLen + udpHdrLen + len(data)
	packet := make([]byte, totalLen)
	
	// Build UDP header
	udpHeader := header.UDP(packet[ipHdrLen:])
	udpHeader.Encode(&header.UDPFields{
		SrcPort: uint16(dest.Port),  // Source is the original destination
		DstPort: uint16(source.Port), // Destination is the original source
		Length:  uint16(udpHdrLen + len(data)),
	})
	
	// Copy payload
	copy(packet[ipHdrLen+udpHdrLen:], data)
	
	// Build IP header and calculate checksums
	if isIPv4 {
		ipv4Header := header.IPv4(packet)
		ipv4Header.Encode(&header.IPv4Fields{
			TOS:         0,
			TotalLength: uint16(totalLen),
			ID:          0,
			Flags:       0,
			FragmentOffset: 0,
			TTL:         64,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     tcpip.AddrFromSlice(dest.Address.IP()),
			DstAddr:     tcpip.AddrFromSlice(source.Address.IP()),
		})
		ipv4Header.SetChecksum(^ipv4Header.CalculateChecksum())
		
		// Calculate UDP checksum
		xsum := header.PseudoHeaderChecksum(
			header.UDPProtocolNumber,
			tcpip.AddrFromSlice(dest.Address.IP()),
			tcpip.AddrFromSlice(source.Address.IP()),
			uint16(udpHdrLen+len(data)),
		)
		xsum = checksum.Checksum(data, xsum)
		udpHeader.SetChecksum(^udpHeader.CalculateChecksum(xsum))
	} else {
		ipv6Header := header.IPv6(packet)
		ipv6Header.Encode(&header.IPv6Fields{
			TrafficClass:  0,
			FlowLabel:     0,
			PayloadLength: uint16(udpHdrLen + len(data)),
			TransportProtocol: header.UDPProtocolNumber,
			HopLimit:      64,
			SrcAddr:       tcpip.AddrFromSlice(dest.Address.IP()),
			DstAddr:       tcpip.AddrFromSlice(source.Address.IP()),
		})
		
		// Calculate UDP checksum for IPv6
		xsum := header.PseudoHeaderChecksum(
			header.UDPProtocolNumber,
			tcpip.AddrFromSlice(dest.Address.IP()),
			tcpip.AddrFromSlice(source.Address.IP()),
			uint16(udpHdrLen+len(data)),
		)
		xsum = checksum.Checksum(data, xsum)
		udpHeader.SetChecksum(^udpHeader.CalculateChecksum(xsum))
	}
	
	// Write packet to stack
	var proto tcpip.NetworkProtocolNumber
	if isIPv4 {
		proto = header.IPv4ProtocolNumber
	} else {
		proto = header.IPv6ProtocolNumber
	}
	
	buf := buffer.MakeWithData(packet)
	if err := ipStack.WriteRawPacket(defaultNIC, proto, buf); err != nil {
		return 0, errors.New("failed to write packet: " + err.String())
	}
	
	return len(data), nil
}

// HandleUDPPacket processes a raw UDP packet from gVisor
func (t *Handler) HandleUDPPacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer, ipStack *stack.Stack) {
	// Extract packet information
	source := net.UDPDestination(
		net.IPAddress(id.RemoteAddress.AsSlice()),
		net.Port(id.RemotePort),
	)
	dest := net.UDPDestination(
		net.IPAddress(id.LocalAddress.AsSlice()),
		net.Port(id.LocalPort),
	)
	
	// Extract UDP payload
	data := pkt.Data().AsRange().ToSlice()
	if len(data) == 0 {
		return
	}
	
	// Get or create connection for this source
	conn, existing := t.getUDPConn(source, dest, ipStack)
	
	// Create buffer and set UDP destination
	b := buf.New()
	b.Write(data)
	b.UDP = &dest
	
	// Write to connection pipe
	conn.writer.WriteMultiBuffer(buf.MultiBuffer{b})
	
	if !existing {
		// Start checker for cleanup (only once)
		t.Lock()
		if t.udpChecker != nil && len(t.udpConns) == 1 {
			common.Must(t.udpChecker.Start())
		}
		t.Unlock()
		
		// Start handling this connection
		go func() {
			connID := udpConnID{
				src: source,
			}
			if !t.cone {
				connID.dest = dest
			}
			
			ctx, cancel := context.WithCancel(t.ctx)
			conn.cancel = cancel
			sid := session.NewID()
			ctx = c.ContextWithID(ctx, sid)
			
			inbound := session.Inbound{}
			inbound.Name = "tun"
			inbound.Source = source
			inbound.User = &protocol.MemoryUser{
				Level: t.config.UserLevel,
			}
			
			ctx = session.ContextWithInbound(ctx, &inbound)
			ctx = session.SubContextFromMuxInbound(ctx)
			
			link := &transport.Link{
				Reader: conn.reader,
				Writer: buf.NewWriter(conn),
			}
			
			if err := t.dispatcher.DispatchLink(ctx, dest, link); err != nil {
				errors.LogError(ctx, errors.New("UDP connection ended").Base(err))
			}
			
			conn.Close()
			if !conn.inactive {
				conn.setInactive()
				t.removeUDPConn(connID)
			}
		}()
	}
}

// Init the Handler instance with necessary parameters
func (t *Handler) Init(ctx context.Context, pm policy.Manager, dispatcher routing.Dispatcher) error {
	var err error

	t.ctx = core.ToBackgroundDetachedContext(ctx)
	t.policyManager = pm
	t.dispatcher = dispatcher
	t.cone = ctx.Value("cone").(bool)
	
	// Initialize UDP connection manager
	t.udpConns = make(map[udpConnID]*udpConn)
	t.udpChecker = &task.Periodic{
		Interval: time.Minute,
		Execute:  t.cleanupUDPConns,
	}

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

	var link *transport.Link
	if destination.Network == net.Network_UDP {
		// For UDP, use PacketReader to preserve packet boundaries
		link = &transport.Link{
			Reader: buf.NewPacketReader(conn),
			Writer: buf.NewWriter(conn),
		}
	} else {
		link = &transport.Link{
			Reader: &buf.TimeoutWrapperReader{Reader: buf.NewReader(conn)},
			Writer: buf.NewWriter(conn),
		}
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
