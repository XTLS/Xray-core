package xdns

import (
	"context"
	"encoding/binary"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

type TCPResolver struct {
	tcpAddr *net.TCPAddr
	udpAddr *net.UDPAddr
	sockopt *internet.SocketConfig

	conn    net.Conn
	readCh  chan []byte
	closeCh chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
}

func NewTCPResolver(config *TCPResolverProto) (Resolver, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", config.Addr)
	if err != nil {
		return nil, err
	}
	return &TCPResolver{tcpAddr: tcpAddr, udpAddr: &net.UDPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port}, sockopt: config.Sockopt}, nil
}

func (r *TCPResolver) closed() bool {
	select {
	case <-r.closeCh:
		return true
	default:
		return false
	}
}

func (r *TCPResolver) dial() net.Conn {
	if r.closed() {
		return nil
	}
	if r.conn != nil {
		return r.conn
	}
	conn, err := internet.DialSystem(context.Background(), net.TCPDestination(net.IPAddress(r.tcpAddr.IP), net.Port(r.tcpAddr.Port)), r.sockopt)
	if err != nil {
		return nil
	}
	r.conn = conn
	r.wg.Add(1)
	go r.recv(conn)
	return r.conn
}

func (r *TCPResolver) recv(conn net.Conn) {
	defer r.wg.Done()

	var buf [4096]byte
	for {
		_, err := io.ReadFull(conn, buf[:2])
		if err != nil {
			break
		}
		n := binary.BigEndian.Uint16(buf[:2])
		if n == 0 || n > 4096 {
			io.CopyN(io.Discard, conn, int64(n))
			continue
		}
		_, err = io.ReadFull(conn, buf[:n])
		if err != nil {
			break
		}
		p := pool4K.Get().([]byte)
		copy(p, buf[:n])
		select {
		case <-r.closeCh:
			pool4K.Put(p[:cap(p)])
		case r.readCh <- p[:n]:
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	conn.Close()
	r.conn = nil
}

func (r *TCPResolver) Addr() *net.UDPAddr {
	return r.udpAddr
}

func (r *TCPResolver) Read(p []byte) (n int, err error) {
	packet, ok := <-r.readCh
	if ok {
		n = copy(p, packet)
		pool4K.Put(packet[:cap(packet)])
		return n, nil
	}
	return 0, io.ErrClosedPipe
}

func (r *TCPResolver) Send(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	conn := r.dial()
	if conn == nil {
		return
	}
	_, _ = conn.Write(p)
}

func (r *TCPResolver) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed() {
		return
	}
	close(r.closeCh)
	if r.conn != nil {
		r.conn.Close()
	}
	r.wg.Wait()
	select {
	case p := <-r.readCh:
		pool4K.Put(p[:cap(p)])
	default:
	}
	close(r.readCh)
}
