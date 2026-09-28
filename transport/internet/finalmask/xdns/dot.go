package xdns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	goerrors "errors"
	"io"
	stdnet "net"
	"sync"

	"github.com/xtls/xray-core/common/errors"
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

type dotResolver struct {
	spec   resolverSpec
	dialer *finalmask.Dialer

	mu      sync.Mutex
	conn    *tls.Conn
	pending map[uint16]dotPending
	closed  bool
	sem     chan struct{}
	readWG  sync.WaitGroup
}

func newDOTResolver(spec resolverSpec, dialer *finalmask.Dialer) *dotResolver {
	return &dotResolver{
		spec:    spec,
		dialer:  dialer,
		pending: make(map[uint16]dotPending),
		sem:     make(chan struct{}, resolverMaxConcurrent),
	}
}

func (r *dotResolver) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, stdnet.ErrClosed
	}
	conn, err := r.connectLocked(ctx)
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	query, id, pending := r.reserveIDLocked(query)
	frame := make([]byte, len(query)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	_, err = conn.Write(frame)
	if err != nil {
		delete(r.pending, id)
		r.mu.Unlock()
		r.failConnection(conn, err)
		return nil, err
	}
	r.mu.Unlock()

	select {
	case result := <-pending.result:
		return result.response, result.err
	case <-ctx.Done():
		r.mu.Lock()
		delete(r.pending, id)
		r.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (r *dotResolver) connectLocked(ctx context.Context) (*tls.Conn, error) {
	if r.conn != nil {
		return r.conn, nil
	}
	host, portString, err := stdnet.SplitHostPort(r.spec.server)
	if err != nil {
		return nil, err
	}
	port, err := xnet.PortFromString(portString)
	if err != nil {
		return nil, err
	}
	raw, err := dialResolverTCP(ctx, r.dialer, xnet.TCPDestination(xnet.ParseAddress(host), port))
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	r.conn = conn
	r.readWG.Add(1)
	go func() {
		defer r.readWG.Done()
		r.readLoop(conn)
	}()
	return conn, nil
}

func dialResolverTCP(ctx context.Context, dialer *finalmask.Dialer, dest xnet.Destination) (stdnet.Conn, error) {
	if dialer.DialTCPContext != nil {
		return dialer.DialTCPContext(ctx, dest)
	}
	if dialer.DialTCP == nil {
		return nil, errors.New("resolver tcp dialer is unavailable")
	}
	return dialer.DialTCP(dest)
}

func (r *dotResolver) reserveIDLocked(query []byte) ([]byte, uint16, dotPending) {
	query = append([]byte(nil), query...)
	id := binary.BigEndian.Uint16(query[:2])
	for {
		if _, found := r.pending[id]; !found {
			break
		}
		id++
	}
	binary.BigEndian.PutUint16(query[:2], id)
	pending := dotPending{query: query, result: make(chan dotResult, 1)}
	r.pending[id] = pending
	return query, id, pending
}

func (r *dotResolver) readLoop(conn *tls.Conn) {
	for {
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			r.failConnection(conn, err)
			return
		}
		length := binary.BigEndian.Uint16(size[:])
		if length < 2 {
			r.failConnection(conn, goerrors.New("invalid dot response length"))
			return
		}
		response := make([]byte, length)
		if _, err := io.ReadFull(conn, response); err != nil {
			r.failConnection(conn, err)
			return
		}
		id := binary.BigEndian.Uint16(response[:2])
		r.mu.Lock()
		pending, found := r.pending[id]
		if found && matchesDNSQuestion(pending.query, response) {
			delete(r.pending, id)
		} else {
			found = false
		}
		r.mu.Unlock()
		if found {
			pending.result <- dotResult{response: response}
		}
	}
}

func (r *dotResolver) failConnection(conn *tls.Conn, err error) {
	r.mu.Lock()
	if r.conn != conn {
		r.mu.Unlock()
		return
	}
	r.conn = nil
	pending := r.pending
	r.pending = make(map[uint16]dotPending)
	r.mu.Unlock()
	_ = conn.Close()
	for _, pending := range pending {
		pending.result <- dotResult{err: err}
	}
	errors.LogDebug(context.Background(), "xdns dot connection closed: ", err)
}

func (r *dotResolver) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	conn := r.conn
	r.conn = nil
	pending := r.pending
	r.pending = make(map[uint16]dotPending)
	r.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	for _, pending := range pending {
		pending.result <- dotResult{err: stdnet.ErrClosed}
	}
	r.readWG.Wait()
	return nil
}

func matchesDNSQuestion(query, response []byte) bool {
	q, err := MessageFromWireFormat(query)
	if err != nil || len(q.Question) != 1 {
		return false
	}
	r, err := MessageFromWireFormat(response)
	if err != nil || len(r.Question) != 1 {
		return false
	}
	return q.Question[0].Type == r.Question[0].Type &&
		q.Question[0].Class == r.Question[0].Class &&
		q.Question[0].Name.String() == r.Question[0].Name.String()
}
