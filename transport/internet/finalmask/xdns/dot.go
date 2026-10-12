package xdns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type doTResult struct {
	message []byte
	err error
}

type doTPending struct {
	query []byte
	originalID uint16
	result chan doTResult
}

type doTConnection struct {
	conn *tls.Conn
	writeGate chan struct{}
	done chan struct{}
	pending map[uint16]*doTPending
	nextID uint32
	closed bool
	err error
}

type DoTResolver struct {
	*requestResolver
	dest xnet.Destination
	dialer *finalmask.Dialer
	tlsConfig *tls.Config
	dialGate chan struct{}
	mu sync.Mutex
	conn *doTConnection
	transportClosed bool
	wg sync.WaitGroup
}

func NewDoTResolver(config *ResolverProto, dialer *finalmask.Dialer) (Resolver, error) {
	if config == nil || dialer == nil || dialer.DialTCPContext == nil {
		return nil, errors.New("DoT requires a context-aware TCP dialer")
	}
	dest, addr, err := resolverTarget(config.Addr, config.Bootstrap, xnet.Network_TCP)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(config.Addr)
	if config.ServerName != "" {
		host = config.ServerName
	}
	tlsConfig, err := resolverTLSConfig(config, host, "dot")
	if err != nil {
		return nil, err
	}
	r := &DoTResolver{dest: dest, dialer: dialer, tlsConfig: tlsConfig, dialGate: make(chan struct{}, 1)}
	r.requestResolver = newRequestResolver(addr, r.exchange, r.closeTransport)
	return r, nil
}

func (r *DoTResolver) connection(ctx context.Context) (*doTConnection, error) {
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
	if previous != nil && previous.nextID < 1<<16 {
		r.mu.Unlock()
		return previous, nil
	}
	if previous != nil && len(previous.pending) != 0 {
		r.mu.Unlock()
		return nil, errors.New("DoT transaction ID space is exhausted with requests pending")
	}
	r.mu.Unlock()
	if previous != nil {
		r.dropConnection(previous, errors.New("DoT transaction ID space exhausted"))
	}
	raw, err := r.dialer.DialTCPContext(ctx, r.dest)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, errors.New("DoT TCP dialer returned no connection")
	}
	conn := tls.Client(raw, r.tlsConfig.Clone())
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	if protocol := conn.ConnectionState().NegotiatedProtocol; protocol != "" && protocol != "dot" {
		raw.Close()
		return nil, errors.New("DoT negotiated an unexpected ALPN")
	}
	c := &doTConnection{conn: conn, writeGate: make(chan struct{}, 1), done: make(chan struct{}), pending: make(map[uint16]*doTPending)}
	r.mu.Lock()
	if r.transportClosed || ctx.Err() != nil {
		r.mu.Unlock()
		raw.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, io.ErrClosedPipe
	}
	r.conn = c
	r.wg.Add(1)
	r.mu.Unlock()
	go r.recv(c)
	return c, nil
}

func (r *DoTResolver) exchange(ctx context.Context, query []byte) ([]byte, error) {
	if err := validateDNSQuery(query); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, resolverRequestTimeout)
	stopClose := context.AfterFunc(r.requestResolver.ctx, cancel)
	defer stopClose()
	defer cancel()
	c, err := r.connection(ctx)
	if err != nil {
		return nil, err
	}
	select {
	case c.writeGate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, c.err
	}
	if err := ctx.Err(); err != nil {
		<-c.writeGate
		return nil, err
	}
	r.mu.Lock()
	if c.closed || c.nextID >= 1<<16 {
		r.mu.Unlock()
		<-c.writeGate
		return nil, errors.New("DoT connection cannot accept a new transaction")
	}
	id := uint16(c.nextID)
	c.nextID++ // Never reuse a wire ID on this connection, including after cancellation.
	wire := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(wire[:2], id)
	pending := &doTPending{query: wire, originalID: binary.BigEndian.Uint16(query[:2]), result: make(chan doTResult, 1)}
	c.pending[id] = pending
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(c.pending, id)
		r.mu.Unlock()
	}()
	deadline, _ := ctx.Deadline()
	err = c.conn.SetWriteDeadline(deadline)
	if err == nil {
		err = c.conn.SetReadDeadline(time.Now().Add(resolverRequestTimeout))
	}
	writeCancelled := make(chan struct{})
	stopWrite := context.AfterFunc(ctx, func() {
		c.conn.SetWriteDeadline(time.Now())
		close(writeCancelled)
	})
	if err == nil {
		err = writeDNSFrame(c.conn, wire)
	}
	if !stopWrite() {
		<-writeCancelled
	}
	// Deadline cleanup must not overwrite a complete response received before peer close.
	_ = c.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		r.dropConnection(c, err)
		<-c.writeGate
		return nil, err
	}
	<-c.writeGate
	select {
	case result := <-pending.result:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return result.message, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		select {
		case result := <-pending.result:
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return result.message, result.err
		default:
		}
		return nil, c.err
	}
}

func (r *DoTResolver) recv(c *doTConnection) {
	defer r.wg.Done()
	for {
		if err := c.conn.SetReadDeadline(time.Now().Add(resolverRequestTimeout)); err != nil {
			r.dropConnection(c, err)
			return
		}
		response, err := readDNSFrame(c.conn)
		if err != nil {
			r.dropConnection(c, err)
			return
		}
		id := binary.BigEndian.Uint16(response[:2])
		r.mu.Lock()
		pending := c.pending[id]
		delete(c.pending, id)
		r.mu.Unlock()
		if pending == nil {
			continue
		}
		if err := validateDNSResponse(pending.query, response); err != nil {
			pending.result <- doTResult{err: err}
			continue
		}
		binary.BigEndian.PutUint16(response[:2], pending.originalID)
		pending.result <- doTResult{message: response}
	}
}

func (r *DoTResolver) dropConnection(c *doTConnection, err error) {
	r.mu.Lock()
	if c.closed {
		r.mu.Unlock()
		return
	}
	c.closed, c.err = true, err
	if r.conn == c {
		r.conn = nil
	}
	pending := c.pending
	c.pending = nil
	close(c.done)
	r.mu.Unlock()
	c.conn.NetConn().Close()
	for _, request := range pending {
		request.result <- doTResult{err: err}
	}
}

func (r *DoTResolver) closeTransport() {
	r.mu.Lock()
	r.transportClosed = true
	c := r.conn
	r.mu.Unlock()
	if c != nil {
		r.dropConnection(c, io.ErrClosedPipe)
	}
	r.wg.Wait()
}
