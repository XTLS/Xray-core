package xdns

import (
	"errors"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type UDPResolver struct {
	dest   net.Destination
	dialer *finalmask.Dialer

	conn    net.PacketConn
	udpAddr *net.UDPAddr

	readCh  chan []byte
	closeCh chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
}

func NewUDPResolver(config *UDPResolverProto, dialer *finalmask.Dialer) (Resolver, error) {
	dest, err := net.ParseDestination("udp:" + config.Addr)
	if err != nil {
		return nil, err
	}
	r := &UDPResolver{
		dest:    dest,
		dialer:  dialer,
		readCh:  make(chan []byte),
		closeCh: make(chan struct{}),
	}
	if err := r.dial(); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

func (r *UDPResolver) closed() bool {
	select {
	case <-r.closeCh:
		return true
	default:
		return false
	}
}

func (r *UDPResolver) dial() error {
	if r.closed() {
		return errors.New("closed")
	}
	if r.conn != nil {
		return nil
	}
	conn, err := r.dialer.DialUDP(r.dest)
	if err != nil {
		return err
	}
	r.conn = conn.(*finalmask.PacketConnWrapper).PacketConn
	r.udpAddr = conn.RemoteAddr().(*net.UDPAddr)
	r.wg.Add(1)
	go r.recv(conn.(*finalmask.PacketConnWrapper).PacketConn)
	return nil
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

	_ = conn.Close()
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
	if err := r.dial(); err != nil {
		return
	}
	_, _ = r.conn.WriteTo(p, r.udpAddr)
}

func (r *UDPResolver) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed() {
		return
	}
	close(r.closeCh)
	if r.conn != nil {
		_ = r.conn.Close()
	}
	r.wg.Wait()
	close(r.readCh)
}
