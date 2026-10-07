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

type dotResult struct {
	response []byte
	err      error
}

type dotPending struct {
	query  []byte
	result chan dotResult
}

type dotTransport struct {
	dest      xnet.Destination
	dialer    *finalmask.Dialer
	tlsConfig *tls.Config
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	conn      *tls.Conn
	pending   map[uint16]dotPending
	nextID    uint16
	closed    bool
	wg        sync.WaitGroup
}

func NewDOTResolver(config *ResolverProto, dialer *finalmask.Dialer) (Resolver, error) {
	config, err := normalizeResolver(config)
	if err != nil {
		return nil, err
	}
	if config.Type != "dot" || dialer == nil || (dialer.DialTCP == nil && dialer.DialTCPContext == nil) {
		return nil, errors.New("invalid DoT resolver or TCP dialer")
	}
	dest, err := xnet.ParseDestination("tcp:" + config.Addr)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(config.Addr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	transport := &dotTransport{
		dest:      dest,
		dialer:    dialer,
		tlsConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
		ctx:       ctx,
		cancel:    cancel,
		pending:   make(map[uint16]dotPending),
	}
	return newEncryptedResolver(transport, dest), nil
}

func (r *dotTransport) connectLocked(ctx context.Context) error {
	if r.closed {
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.conn != nil {
		return nil
	}
	raw, err := dialResolverTCP(ctx, r.dialer, r.dest)
	if err != nil {
		return err
	}
	conn := tls.Client(raw, r.tlsConfig)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return err
	}
	r.conn = conn
	r.wg.Add(1)
	go r.recv(conn)
	return nil
}

func (r *dotTransport) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) < 12 || len(query) > resolverMaxResponse {
		return nil, errors.New("invalid DoT query length")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopClose := context.AfterFunc(r.ctx, cancel)
	defer stopClose()
	if r.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	originalID := binary.BigEndian.Uint16(query[:2])
	query = append([]byte(nil), query...)
	r.mu.Lock()
	if err := r.connectLocked(ctx); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	id := r.nextID
	for {
		if _, found := r.pending[id]; !found {
			break
		}
		id++
	}
	r.nextID = id + 1
	binary.BigEndian.PutUint16(query[:2], id)
	pending := dotPending{query: query, result: make(chan dotResult, 1)}
	r.pending[id] = pending
	frame := make([]byte, len(query)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	conn := r.conn
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	}
	wakeDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		// Proxy-backed connections may ignore SetWriteDeadline. Closing the
		// underlying stream also interrupts a blocked TLS write in that case.
		_ = conn.NetConn().Close()
		close(wakeDone)
	})
	n, err := conn.Write(frame)
	if !stop() {
		<-wakeDone
	}
	_ = conn.SetWriteDeadline(time.Time{})
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	if err != nil {
		r.failLocked(conn, err)
		r.mu.Unlock()
		return nil, err
	}
	r.mu.Unlock()
	select {
	case result := <-pending.result:
		if result.err == nil {
			binary.BigEndian.PutUint16(result.response[:2], originalID)
		}
		return result.response, result.err
	case <-ctx.Done():
		r.mu.Lock()
		// A disconnected connection may have been replaced; do not remove a
		// different request after the 16-bit ID has wrapped around.
		if current, ok := r.pending[id]; ok && current.result == pending.result {
			delete(r.pending, id)
		}
		r.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (r *dotTransport) recv(conn *tls.Conn) {
	defer r.wg.Done()
	for {
		var header [2]byte
		_, err := io.ReadFull(conn, header[:])
		length := int(binary.BigEndian.Uint16(header[:]))
		if err == nil && (length < 12 || length > resolverMaxResponse) {
			err = errors.New("invalid DoT response length")
		}
		var response []byte
		if err == nil {
			response = make([]byte, length)
			_, err = io.ReadFull(conn, response)
		}
		r.mu.Lock()
		if err != nil {
			r.failLocked(conn, err)
			r.mu.Unlock()
			return
		}
		id := binary.BigEndian.Uint16(response[:2])
		pending, found := r.pending[id]
		if r.conn == conn && found && matchesDNSQuestion(pending.query, response) {
			delete(r.pending, id)
			pending.result <- dotResult{response: response}
		}
		r.mu.Unlock()
	}
}

func (r *dotTransport) failLocked(conn *tls.Conn, err error) {
	if r.conn != conn {
		return
	}
	r.conn = nil
	_ = conn.NetConn().Close()
	for id, pending := range r.pending {
		pending.result <- dotResult{err: err}
		delete(r.pending, id)
	}
}

func (r *dotTransport) Close() {
	r.cancel()
	r.mu.Lock()
	r.closed = true
	if r.conn != nil {
		r.failLocked(r.conn, net.ErrClosed)
	}
	r.mu.Unlock()
	r.wg.Wait()
}
