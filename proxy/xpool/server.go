package xpool

import (
	"context"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/xpool"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

type Server struct {
	dispatcher routing.Dispatcher
	pool       *xpool.ConnectionPool
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	s := &Server{
		pool: xpool.NewConnectionPool(xpool.PoolConfig{MaxIdle: 100, IdleTimeout: 120}, nil),
	}
	core.RequireFeatures(ctx, func(d routing.Dispatcher) {
		s.dispatcher = d
	})
	s.pool.SetNewSessionCallback(s.onNewSession)
	return s, nil
}

func (s *Server) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	rwc := &LinkRWC{Reader: link.Reader, Writer: link.Writer}
	conn := xpool.NewGatewayConn(rwc, s.pool)
	<-conn.Done()
	return nil
}

func (s *Server) onNewSession(conn *xpool.GatewayConn, seg *xpool.Segment) xpool.Session {
	if seg.SID == 0 {
		return nil
	}
	errors.LogDebug(nil, "new server session ", seg.SID)
	session := xpool.NewServerSession(seg.SID, conn)
	go s.handleSession(session)
	return session
}

var addrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv4), net.AddressFamilyIPv4),
	protocol.AddressFamilyByte(byte(protocol.AddressTypeDomain), net.AddressFamilyDomain),
	protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv6), net.AddressFamilyIPv6),
	protocol.PortThenAddress(),
)

func (s *Server) handleSession(session *xpool.ServerSession) {
	// 1. Read first payload (Target)
	mb, err := session.ReadMultiBuffer()
	if err != nil {
		return
	}

	reader := &buf.BufferedReader{Reader: &SingleReader{MB: mb}}

	addr, port, err := addrParser.ReadAddressPort(nil, reader)
	if err != nil {
		errors.LogWarningInner(nil, err, "failed to read address")
		buf.ReleaseMulti(mb)
		return
	}

	dest := net.TCPDestination(addr, port)
	ctx := context.Background()

	link, err := s.dispatcher.Dispatch(ctx, dest)
	if err != nil {
		errors.LogWarningInner(nil, err, "failed to dispatch")
		buf.ReleaseMulti(mb) // Release remaining if any
		return
	}

	session.TargetWriter = link.Writer

	if reader.BufferedBytes() > 0 {
		mb, _ := reader.ReadMultiBuffer()
		link.Writer.WriteMultiBuffer(mb)
	}

	// Proxy Response Loop
	go func() {
		defer session.Close() // Close session when target closes
		sw := &SessionWriter{session}
		buf.Copy(link.Reader, sw)
	}()

	// Proxy Request Loop
	sr := &SessionReader{session}
	buf.Copy(sr, link.Writer)
}

// Helpers

type LinkRWC struct {
	Reader buf.Reader
	Writer buf.Writer
	buffer buf.MultiBuffer
}

func (l *LinkRWC) Read(p []byte) (int, error) {
	if l.buffer.IsEmpty() {
		mb, err := l.Reader.ReadMultiBuffer()
		if err != nil {
			return 0, err
		}
		l.buffer = mb
	}

	var n int
	l.buffer, n = buf.SplitBytes(l.buffer, p)
	return n, nil
}

func (l *LinkRWC) Write(p []byte) (int, error) {
	b := buf.New()
	b.Write(p)
	if err := l.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		b.Release()
		return 0, err
	}
	return len(p), nil
}

func (l *LinkRWC) Close() error {
	return common.Close(l.Writer)
}

type SingleReader struct {
	MB buf.MultiBuffer
}

func (r *SingleReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.MB.IsEmpty() {
		return nil, io.EOF
	}
	mb := r.MB
	r.MB = nil
	return mb, nil
}

type SessionReader struct {
	s *xpool.ServerSession
}

func (r *SessionReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.s.ReadMultiBuffer()
}

type SessionWriter struct {
	s *xpool.ServerSession
}

func (w *SessionWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.s.WriteMultiBuffer(mb)
}
