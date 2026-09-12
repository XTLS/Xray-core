package xdns

import (
	"context"
	"io"
	"reflect"
	"sync"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/transport/internet"
)

type UDPResolver struct {
	udpAddr *net.UDPAddr
	sockopt *internet.SocketConfig

	conn    net.PacketConn
	readCh  chan []byte
	closeCh chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
}

func NewUDPResolver(config *UDPResolverProto) (Resolver, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", config.Addr)
	if err != nil {
		return nil, err
	}
	return &UDPResolver{udpAddr: udpAddr, sockopt: config.Sockopt}, nil
}

func (r *UDPResolver) closed() bool {
	select {
	case <-r.closeCh:
		return true
	default:
		return false
	}
}

func (r *UDPResolver) dial() net.PacketConn {
	if r.closed() {
		return nil
	}
	if r.conn != nil {
		return r.conn
	}
	conn, err := internet.DialSystem(context.Background(), net.UDPDestination(net.IPAddress(r.udpAddr.IP), net.Port(r.udpAddr.Port)), r.sockopt)
	if err != nil {
		return nil
	}
	var newConn net.PacketConn
	switch c := conn.(type) {
	case *internet.PacketConnWrapper:
		newConn = c.PacketConn
	case *cnc.Connection:
		newConn = &internet.FakePacketConn{Conn: c}
	default:
		panic(reflect.TypeOf(c))
	}
	r.conn = newConn
	r.wg.Add(1)
	go r.recv(newConn)
	return r.conn
}

func (r *UDPResolver) recv(conn net.PacketConn) {
	defer r.wg.Done()

	var buf [4096]byte
	for {
		n, _, err := conn.ReadFrom(buf[:])
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

func (r *UDPResolver) Addr() *net.UDPAddr {
	return r.udpAddr
}

func (r *UDPResolver) Read(p []byte) (n int, err error) {
	packet, ok := <-r.readCh
	if ok {
		n = copy(p, packet)
		pool4K.Put(packet[:cap(packet)])
		return n, nil
	}
	return 0, io.ErrClosedPipe
}

func (r *UDPResolver) Send(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	conn := r.dial()
	if conn == nil {
		return
	}
	_, _ = conn.WriteTo(p, r.udpAddr)
}

func (r *UDPResolver) Close() {
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
