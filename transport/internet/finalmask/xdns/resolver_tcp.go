package xdns

import (
	"context"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type TCPResolver struct {
	dest   net.Destination
	dialer *finalmask.Dialer

	udpAddr *net.UDPAddr
	readCh  chan []byte
	sendCh  chan []byte
	closeCh chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
}

func NewTCPResolver(config *ResolverProto, dialer *finalmask.Dialer) (Resolver, error) {
	dest, err := net.ParseDestination("tcp:" + config.Addr)
	if err != nil {
		return nil, err
	}
	r := &TCPResolver{
		dest:    dest,
		dialer:  dialer,
		readCh:  make(chan []byte),
		sendCh:  make(chan []byte),
		closeCh: make(chan struct{}),
	}
	go r.run(config.Worker)
	return r, nil
}

func (r *TCPResolver) closed() bool {
	select {
	case <-r.closeCh:
		return true
	default:
		return false
	}
}

func (r *TCPResolver) setaddr(addr net.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch v := addr.(type) {
	case *net.TCPAddr:
		r.udpAddr = &net.UDPAddr{IP: v.IP, Port: v.Port}
	case *net.UDPAddr:
		r.udpAddr = v
	default:
		panic(v)
	}
}

func (r *TCPResolver) read(reader io.Reader, p []byte) (l int, err error) {
	if _, err := io.ReadFull(reader, p[:2]); err != nil {
		return 0, err
	}
	l = int(p[0])<<8 | int(p[1])
	if l == 0 || l > 4096 {
		return 0, errors.New("err resp len ", l)
	}
	if _, err = io.ReadFull(reader, p[:l]); err != nil {
		return 0, err
	}
	return l, nil
}

func (r *TCPResolver) do(conn *net.Conn, buf *[4096 + 2]byte, p []byte) error {
	var err error
	if *conn == nil {
		*conn, err = r.dialer.DialTCP(r.dest)
		if err != nil {
			*conn = nil
			return err
		}
		r.setaddr((*conn).RemoteAddr())
	}

	c := *conn
	l := len(p)
	buf[0] = byte(l >> 8)
	buf[1] = byte(l)
	copy(buf[2:], p)
	_, err = c.Write(buf[:2+len(p)])
	if err != nil {
		c.Close()
		*conn = nil
		return err
	}

	b := pool4K.Get().([]byte)
	l, err = r.read(c, b)
	if err != nil {
		c.Close()
		*conn = nil
		pool4K.Put(b[:cap(b)])
		return err
	}
	select {
	case <-r.closeCh:
		pool4K.Put(b[:cap(b)])
	case r.readCh <- b[:l]:
	}
	return nil
}

func (r *TCPResolver) worker() {
	defer r.wg.Done()

	var conn net.Conn
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	var buf [4096 + 2]byte
	var p []byte
	for {
		select {
		case <-r.closeCh:
			return
		default:
			select {
			case <-r.closeCh:
				return
			case p = <-r.sendCh:
			}
		}
		if err := r.do(&conn, &buf, p); err != nil {
			errors.LogErrorInner(context.Background(), err, "do err")
		}
	}
}

func (r *TCPResolver) run(worker int32) {
	for range worker {
		r.wg.Add(1)
		go r.worker()
	}
	r.wg.Wait()
	close(r.readCh)
	// close(r.sendCh)
}

func (r *TCPResolver) Addr() *net.UDPAddr {
	r.mu.Lock()
	defer r.mu.Unlock()
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
	select {
	case <-r.closeCh:
		return
	default:
		b := make([]byte, len(p))
		copy(b, p)
		select {
		case <-r.closeCh:
			return
		case r.sendCh <- b:
		}
	}
}

func (r *TCPResolver) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed() {
		return
	}
	close(r.closeCh)
}
