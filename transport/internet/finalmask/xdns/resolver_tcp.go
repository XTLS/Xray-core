package xdns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type TCPResolver struct { *socketResolver }

// socketResolver keeps the existing synchronous UDP/TCP send contract.
type socketResolver struct {
	ctx context.Context
	cancel context.CancelFunc
	dial func(context.Context) (net.Conn, error)
	framed bool
	addr *net.UDPAddr
	conn net.Conn
	readCh chan []byte
	mu sync.Mutex
	sendMu sync.Mutex
	wg sync.WaitGroup
	once sync.Once
}

func NewTCPResolver(config *ResolverProto, dialer *finalmask.Dialer) (Resolver, error) {
	dest, addr, err := resolverTarget(config.Addr, "", net.Network_TCP)
	if err != nil { return nil, err }
	if dialer == nil || (dialer.DialTCPContext == nil && dialer.DialTCP == nil) { return nil, errors.New("missing TCP dialer") }
	r, err := newSocketResolver(addr, true, func(ctx context.Context) (net.Conn, error) {
		if dialer.DialTCPContext != nil { return dialer.DialTCPContext(ctx, dest) }
		return dialer.DialTCP(dest)
	})
	if err != nil { return nil, err }
	return &TCPResolver{r}, nil
}

func newSocketResolver(addr *net.UDPAddr, framed bool, dial func(context.Context) (net.Conn, error)) (*socketResolver, error) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &socketResolver{ctx: ctx, cancel: cancel, addr: addr, framed: framed, dial: dial, readCh: make(chan []byte, resolverQueueSize)}
	if _, err := r.connect(); err != nil { r.Close(); return nil, err }
	return r, nil
}

func (r *socketResolver) connect() (net.Conn, error) {
	r.mu.Lock()
	if r.ctx.Err() != nil { r.mu.Unlock(); return nil, io.ErrClosedPipe }
	if r.conn != nil { conn := r.conn; r.mu.Unlock(); return conn, nil }
	r.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.ctx, resolverRequestTimeout)
	defer cancel()
	conn, err := r.dial(ctx)
	if err != nil { return nil, err }
	if conn == nil { return nil, errors.New("dialer returned nil connection") }
	r.mu.Lock()
	if r.ctx.Err() != nil { r.mu.Unlock(); conn.Close(); return nil, io.ErrClosedPipe }
	r.conn = conn
	r.wg.Add(1)
	go r.recv(conn)
	r.mu.Unlock()
	return conn, nil
}

func (r *socketResolver) disconnect(conn net.Conn) {
	r.mu.Lock()
	if r.conn == conn { r.conn = nil }
	r.mu.Unlock()
	conn.Close()
}

func (r *socketResolver) recv(conn net.Conn) {
	defer r.wg.Done()
	defer r.disconnect(conn)
	for {
		var packet []byte
		var err error
		if r.framed {
			packet, err = readDNSFrame(conn)
		} else {
			buf := make([]byte, maxDNSMessageSize+1)
			var n int
			n, err = conn.Read(buf)
			if n > maxDNSMessageSize { continue }
			packet = buf[:n]
		}
		if err != nil { return }
		select {
		case <-r.ctx.Done(): return
		case r.readCh <- packet:
		}
	}
}

func (r *socketResolver) Addr() *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), r.addr.IP...), Port: r.addr.Port, Zone: r.addr.Zone}
}

func (r *socketResolver) Read(p []byte) (int, error) {
	if r.ctx.Err() != nil { return 0, io.ErrClosedPipe }
	select {
	case <-r.ctx.Done(): return 0, io.ErrClosedPipe
	case packet := <-r.readCh:
		if len(p) < len(packet) { return 0, io.ErrShortBuffer }
		return copy(p, packet), nil
	}
}

func (r *socketResolver) Send(p []byte) error {
	if len(p) < 12 || len(p) > maxDNSMessageSize { return errors.New("invalid DNS message length") }
	r.sendMu.Lock()
	defer r.sendMu.Unlock()
	conn, err := r.connect()
	if err != nil { return err }
	if err = conn.SetWriteDeadline(time.Now().Add(resolverRequestTimeout)); err == nil {
		if r.framed {
			err = writeDNSFrame(conn, p)
		} else {
			var n int
			n, err = conn.Write(p)
			if err == nil && n != len(p) { err = io.ErrShortWrite }
		}
	}
	if err != nil { r.disconnect(conn) }
	return err
}

func (r *socketResolver) Close() {
	r.once.Do(func() {
		r.cancel()
		r.mu.Lock()
		conn := r.conn
		r.conn = nil
		r.mu.Unlock()
		if conn != nil { conn.Close() }
		r.wg.Wait()
	})
}

func writeDNSFrame(w io.Writer, p []byte) error {
	if len(p) < 12 || len(p) > maxDNSMessageSize { return errors.New("invalid DNS frame length") }
	frame := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(frame, uint16(len(p)))
	copy(frame[2:], p)
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil { return err }
		if n <= 0 || n > len(frame) { return io.ErrShortWrite }
		frame = frame[n:]
	}
	return nil
}

func readDNSFrame(r io.Reader) ([]byte, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil { return nil, err }
	n := int(binary.BigEndian.Uint16(prefix[:]))
	if n < 12 || n > maxDNSMessageSize { return nil, errors.New("invalid DNS frame length") }
	packet := make([]byte, n)
	_, err := io.ReadFull(r, packet)
	return packet, err
}
