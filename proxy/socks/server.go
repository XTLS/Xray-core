package socks

import (
	"bytes"
	"context"
	goerrors "errors"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/http"
	"github.com/xtls/xray-core/transport/exchange"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Server is a SOCKS 5 proxy server
type Server struct {
	config        *ServerConfig
	policyManager policy.Manager
	cone          bool
	httpServer    *http.Server
}

// NewServer creates a new Server object.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	v := core.MustFromContext(ctx)
	s := &Server{
		config:        config,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		cone:          ctx.Value("cone").(bool),
	}
	httpConfig := &http.ServerConfig{
		UserLevel: config.UserLevel,
	}
	if config.AuthType == AuthType_PASSWORD {
		httpConfig.Accounts = config.Accounts
	}
	s.httpServer, _ = http.NewServer(ctx, httpConfig)
	return s, nil
}

func (s *Server) policy() policy.Session {
	config := s.config
	p := s.policyManager.ForLevel(config.UserLevel)
	return p
}

// Network implements proxy.Inbound.
func (s *Server) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

// Process implements proxy.Inbound.
func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "socks"
	inbound.CanSpliceCopy = 2
	inbound.User = &protocol.MemoryUser{
		Level: s.config.UserLevel,
	}
	if !proxy.IsRAWTransportWithoutSecurity(conn) {
		inbound.CanSpliceCopy = 3
	}

	switch network {
	case net.Network_TCP:
		firstbyte := make([]byte, 1)
		if n, err := conn.Read(firstbyte); n == 0 {
			if goerrors.Is(err, io.EOF) {
				errors.LogInfo(ctx, "Connection closed immediately, likely health check connection")
				return nil
			}
			return errors.New("failed to read from connection").Base(err)
		}
		if firstbyte[0] != 5 && firstbyte[0] != 4 { // Check if it is Socks5/4/4a
			errors.LogDebug(ctx, "Not Socks request, try to parse as HTTP request")
			return s.httpServer.ProcessWithFirstbyte(ctx, network, conn, dispatcher, firstbyte...)
		}
		return s.processTCP(ctx, conn, dispatcher, firstbyte)
	default:
		return errors.New("unknown network: ", network)
	}
}

func (s *Server) processTCP(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher, firstbyte []byte) error {
	plcy := s.policy()
	if err := conn.SetReadDeadline(time.Now().Add(plcy.Timeouts.Handshake)); err != nil {
		errors.LogInfoInner(ctx, err, "failed to set deadline")
	}

	inbound := session.InboundFromContext(ctx)
	if inbound == nil || !inbound.Gateway.IsValid() {
		return errors.New("inbound gateway not specified")
	}

	svrSession := &ServerSession{
		config:       s.config,
		address:      inbound.Gateway.Address,
		port:         inbound.Gateway.Port,
		localAddress: net.IPAddress(conn.LocalAddr().(*net.TCPAddr).IP),
	}

	// Firstbyte is for forwarded conn from SOCKS inbound
	// Because it needs first byte to choose protocol
	// We need to add it back
	reader := io.MultiReader(bytes.NewReader(firstbyte), conn)
	request, tempUDPConn, err := svrSession.Handshake(reader, conn)
	defer common.CloseIfExists(tempUDPConn)
	if err != nil {
		if inbound.Source.IsValid() {
			log.Record(&log.AccessMessage{
				From:   inbound.Source,
				To:     "",
				Status: log.AccessRejected,
				Reason: err,
			})
		}
		return errors.New("failed to read request").Base(err)
	}
	if request.User != nil {
		inbound.User.Email = request.User.Email
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		errors.LogInfoInner(ctx, err, "failed to clear deadline")
	}

	if request.Command == protocol.RequestCommandTCP {
		dest := request.Destination()
		errors.LogInfo(ctx, "TCP Connect request to ", dest)
		if inbound.Source.IsValid() {
			ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
				From:   inbound.Source,
				To:     dest,
				Status: log.AccessAccepted,
				Reason: "",
			})
		}
		if inbound.CanSpliceCopy == 2 {
			inbound.CanSpliceCopy = 1
		}
		rawConn := stat.TryUnwrapStatsConn(conn)
		_, rawTCP := rawConn.(*net.TCPConn)
		source := exchange.Stream{
			Reader: rawConn, Writer: rawConn,
			SetReadDeadline: conn.SetReadDeadline,
			Abort:           func() { _ = conn.Close() },
			NativeRead:      inbound.CanSpliceCopy == 1 && rawTCP,
			NativeWrite:     inbound.CanSpliceCopy == 1 && rawTCP,
		}
		if statsConn, ok := conn.(*stat.CounterConnection); ok {
			if statsConn.ReadCounter != nil {
				source.CountRead = func(n int64) { statsConn.ReadCounter.Add(n) }
			}
			if statsConn.WriteCounter != nil {
				source.CountWrite = func(n int64) { statsConn.WriteCounter.Add(n) }
			}
		}
		if half, ok := rawConn.(interface{ CloseRead() error }); ok {
			source.CloseRead = half.CloseRead
		}
		if half, ok := rawConn.(interface{ CloseWrite() error }); ok {
			source.CloseWrite = half.CloseWrite
		}
		if err := routing.DispatchStream(dispatcher, ctx, dest, source); err != nil {
			return errors.New("failed to dispatch request").Base(err)
		}
		return nil
	}

	if request.Command == protocol.RequestCommandUDP {
		if tempUDPConn == nil {
			return errors.New("UDP associate with listen port failed")
		}
		tempUDPConn.SetTimeout(plcy.Timeouts.ConnectionIdle)
		packetCtx, cancelPacket := context.WithCancel(ctx)
		errCh := make(chan error, 1)
		go func() {
			errCh <- s.handleUDPPayload(packetCtx, tempUDPConn, dispatcher)
		}()
		// Associated TCP keeps the UDP alive
		// Close UDP if TCP connection is closed
		// Or Close TCP if UDP is idle timeout
		io.Copy(buf.DiscardBytes, conn)
		cancelPacket()
		tempUDPConn.Close()
		return <-errCh
	}
	return nil
}

// socksPacketSource keeps SOCKS framing inside the protocol owner.
type socksPacketSource struct {
	ctx       context.Context
	conn      stat.Connection
	first     []byte
	firstDest net.Destination
	hasFirst  bool
	pending   error
}

func (p *socksPacketSource) ReadPacket(dst []byte) (int, net.Destination, error) {
	if p.hasFirst {
		p.hasFirst = false
		n := copy(dst, p.first)
		p.first = nil
		return n, p.firstDest, nil
	}
	for {
		if p.pending != nil {
			err := p.pending
			p.pending = nil
			return 0, net.Destination{}, err
		}
		n, err := p.conn.Read(dst)
		if err != nil && n == 0 {
			return 0, net.Destination{}, err
		}
		if err != nil {
			p.pending = err
		}
		packet := buf.FromBytes(dst[:n])
		request, err := DecodeUDPPacket(packet)
		if err != nil {
			errors.LogInfoInner(p.ctx, err, "failed to parse UDP request")
			continue
		}
		dest := request.Destination()
		payload := packet.Bytes()
		copy(dst, payload)
		return len(payload), dest, nil
	}
}

func (p *socksPacketSource) WritePacket(payload []byte, from net.Destination) (int, error) {
	packet := buf.NewWithSize(int32(len(payload) + 262))
	defer packet.Release()
	if _, err := packet.Write([]byte{0, 0, 0}); err != nil {
		return 0, err
	}
	if err := addrParser.WriteAddressPort(packet, from.Address, from.Port); err != nil {
		return 0, err
	}
	if _, err := packet.Write(payload); err != nil {
		return 0, err
	}
	wire := packet.Bytes()
	n, err := p.conn.Write(wire)
	if err != nil {
		return 0, err
	}
	if n != len(wire) {
		return 0, io.ErrShortWrite
	}
	return len(payload), nil
}

func (s *Server) handleUDPPayload(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher) error {
	source := &socksPacketSource{ctx: ctx, conn: conn}
	firstBuffer := make([]byte, 65535)
	n, first, err := source.ReadPacket(firstBuffer)
	if err != nil {
		return err
	}
	source.first = append([]byte(nil), firstBuffer[:n]...)
	source.firstDest = first
	source.hasFirst = true
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		newInbound := *inbound
		newInbound.Source = net.DestinationFromAddr(conn.RemoteAddr())
		newInbound.Local = net.DestinationFromAddr(conn.LocalAddr())
		ctx = session.ContextWithInbound(ctx, &newInbound)
		source.ctx = ctx
		errors.LogInfo(ctx, "client UDP connection from ", newInbound.Source)
		if newInbound.Source.IsValid() {
			ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{From: newInbound.Source, To: first, Status: log.AccessAccepted, Reason: ""})
		}
	}
	return routing.DispatchPacket(dispatcher, ctx, first, exchange.PacketEndpoint{Reader: source, Writer: source, Abort: func() { _ = conn.Close() }, SetWriteDeadline: conn.SetWriteDeadline})
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
