package xdns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/apernet/quic-go"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	doQProtocolErrorCode quic.ApplicationErrorCode = 2
	doQRequestCancelled quic.StreamErrorCode = 3
)

type doQConnection struct {
	conn *quic.Conn
	transport *quic.Transport
	packet net.PacketConn
	once sync.Once
}

func (c *doQConnection) close(code quic.ApplicationErrorCode, reason string) {
	c.once.Do(func() {
		if c.conn != nil {
			c.conn.CloseWithError(code, reason)
		}
		// Close the socket first because some finalmask PacketConns cannot set read deadlines.
		c.packet.Close()
		c.transport.Close()
	})
}

type DoQResolver struct {
	*requestResolver
	dest xnet.Destination
	dialer *finalmask.Dialer
	tlsConfig *tls.Config
	dialGate chan struct{}
	mu sync.Mutex
	conn *doQConnection
	transportClosed bool
	wg sync.WaitGroup
}

func NewDoQResolver(config *ResolverProto, dialer *finalmask.Dialer) (Resolver, error) {
	if config == nil || dialer == nil || dialer.DialUDPContext == nil {
		return nil, errors.New("DoQ requires a context-aware UDP dialer")
	}
	dest, addr, err := resolverTarget(config.Addr, config.Bootstrap, xnet.Network_UDP)
	if err != nil {
		return nil, err
	}
	if dest.Port == 53 {
		return nil, errors.New("DoQ must not use UDP port 53")
	}
	host, _, _ := net.SplitHostPort(config.Addr)
	if config.ServerName != "" {
		host = config.ServerName
	}
	tlsConfig, err := resolverTLSConfig(config, host, "doq")
	if err != nil {
		return nil, err
	}
	r := &DoQResolver{dest: dest, dialer: dialer, tlsConfig: tlsConfig, dialGate: make(chan struct{}, 1)}
	r.requestResolver = newRequestResolver(addr, r.exchange, r.closeTransport)
	return r, nil
}

func (r *DoQResolver) connection(ctx context.Context) (*doQConnection, error) {
	select {
	case r.dialGate <- struct{}{}:
		defer func() { <-r.dialGate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	r.mu.Lock()
	if r.transportClosed || ctx.Err() != nil {
		r.mu.Unlock()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, io.ErrClosedPipe
	}
	previous := r.conn
	if previous != nil && previous.conn.Context().Err() == nil {
		r.mu.Unlock()
		return previous, nil
	}
	r.mu.Unlock()
	if previous != nil {
		r.dropConnection(previous, 0, "")
	}
	raw, err := r.dialer.DialUDPContext(ctx, r.dest)
	if err != nil {
		return nil, err
	}
	wrapper, ok := raw.(*xnet.PacketConnWrapper)
	if !ok {
		if raw != nil {
			raw.Close()
		}
		return nil, errors.New("DoQ UDP dialer must return a PacketConnWrapper")
	}
	if wrapper == nil || wrapper.PacketConn == nil {
		return nil, errors.New("DoQ UDP dialer returned no PacketConn")
	}
	remote, ok := wrapper.RemoteAddr().(*net.UDPAddr)
	if !ok || remote == nil {
		wrapper.Close()
		return nil, errors.New("DoQ UDP dialer returned no UDP destination")
	}
	c := &doQConnection{packet: wrapper.PacketConn, transport: &quic.Transport{Conn: wrapper.PacketConn}}
	c.conn, err = c.transport.Dial(ctx, remote, r.tlsConfig.Clone(), &quic.Config{
		HandshakeIdleTimeout: resolverRequestTimeout,
		MaxIncomingStreams: -1,
		MaxIncomingUniStreams: -1,
	})
	if err != nil {
		c.close(0, "")
		return nil, err
	}
	if c.conn.ConnectionState().TLS.NegotiatedProtocol != "doq" {
		c.close(doQProtocolErrorCode, "unexpected ALPN")
		return nil, errors.New("DoQ negotiated an unexpected ALPN")
	}
	r.mu.Lock()
	if r.transportClosed || ctx.Err() != nil {
		r.mu.Unlock()
		c.close(0, "")
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, io.ErrClosedPipe
	}
	r.conn = c
	r.wg.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.wg.Done()
		<-c.conn.Context().Done()
		r.dropConnection(c, 0, "")
	}()
	return c, nil
}

func (r *DoQResolver) exchange(ctx context.Context, query []byte) ([]byte, error) {
	if err := validateDNSQuery(query); err != nil {
		return nil, err
	}
	if err := doQCheckEDNS(query); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, resolverRequestTimeout)
	defer cancel()
	stopClose := context.AfterFunc(r.requestResolver.ctx, cancel)
	defer stopClose()
	c, err := r.connection(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	completed := false
	defer func() {
		if !completed {
			stream.CancelRead(doQRequestCancelled)
			stream.CancelWrite(doQRequestCancelled)
		}
	}()
	stopStream := context.AfterFunc(ctx, func() {
		stream.CancelRead(doQRequestCancelled)
		stream.CancelWrite(doQRequestCancelled)
	})
	defer stopStream()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	if err := stream.SetDeadline(deadline); err != nil {
		return nil, err
	}
	wire := append([]byte(nil), query...)
	wire[0], wire[1] = 0, 0
	if err := writeDNSFrame(stream, wire); err != nil {
		var streamError *quic.StreamError
		if errors.As(err, &streamError) && streamError.Remote {
			return r.protocolFailure(c, "unexpected STOP_SENDING")
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if err := stream.Close(); err != nil {
		return nil, err
	}
	response, err := readDoQFrame(stream)
	if err != nil {
		var protocolError *doQProtocolError
		if errors.As(err, &protocolError) {
			return r.protocolFailure(c, protocolError.Error())
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if err := validateDNSResponse(wire, response); err != nil {
		return r.protocolFailure(c, "DNS response does not match DoQ query")
	}
	if err := doQCheckEDNS(response); err != nil {
		return r.protocolFailure(c, "DoQ response contains TCP keepalive")
	}
	var extra [1]byte
	n, err := io.ReadFull(stream, extra[:])
	if n != 0 {
		return r.protocolFailure(c, "additional DoQ response bytes")
	}
	if err != io.EOF {
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, ctx.Err()
		}
		var timeout net.Error
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
			return r.protocolFailure(c, "DoQ response did not end with FIN")
		}
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	copy(response[:2], query[:2])
	completed = true
	return response, nil
}

type doQProtocolError struct { message string }

func (e *doQProtocolError) Error() string { return e.message }

func readDoQFrame(reader io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, &doQProtocolError{"incomplete DoQ length prefix"}
		}
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[:]))
	if length < 12 || length > maxDNSMessageSize {
		return nil, &doQProtocolError{"invalid DoQ message length"}
	}
	message := make([]byte, length)
	if _, err := io.ReadFull(reader, message); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, &doQProtocolError{"incomplete DoQ message"}
		}
		return nil, err
	}
	return message, nil
}

func doQCheckEDNS(message []byte) error {
	var parsed dnsmessage.Message
	if err := parsed.Unpack(message); err != nil {
		return err
	}
	for _, resource := range parsed.Additionals {
		if opt, ok := resource.Body.(*dnsmessage.OPTResource); ok {
			for _, option := range opt.Options {
				if option.Code == 11 {
					return errors.New("TCP keepalive is forbidden in DoQ")
				}
			}
		}
	}
	return nil
}

func (r *DoQResolver) protocolFailure(c *doQConnection, reason string) ([]byte, error) {
	r.dropConnection(c, doQProtocolErrorCode, reason)
	return nil, &doQProtocolError{reason}
}

func (r *DoQResolver) dropConnection(c *doQConnection, code quic.ApplicationErrorCode, reason string) {
	r.mu.Lock()
	if r.conn == c {
		r.conn = nil
	}
	r.mu.Unlock()
	c.close(code, reason)
}

func (r *DoQResolver) closeTransport() {
	r.mu.Lock()
	r.transportClosed = true
	c := r.conn
	r.mu.Unlock()
	if c != nil {
		r.dropConnection(c, 0, "")
	}
	r.wg.Wait()
}
