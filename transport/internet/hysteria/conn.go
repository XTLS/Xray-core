package hysteria

import (
	"context"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/transport/internet"
)

type interConn struct {
	stream *quic.Stream
	local  net.Addr
	remote net.Addr

	client bool
	user   *protocol.MemoryUser
}

func (c *interConn) User() *protocol.MemoryUser {
	return c.user
}

func (c *interConn) Read(b []byte) (int, error) {
	return c.stream.Read(b)
}

func (c *interConn) Write(b []byte) (int, error) {
	if c.client {
		c.client = false
		if _, err := c.stream.Write(append(quicvarint.Append(nil, FrameTypeTCPRequest), b...)); err != nil {
			return 0, err
		}
		return len(b), nil
	}

	return c.stream.Write(b)
}

func (c *interConn) Close() error {
	c.stream.CancelRead(0)
	return c.stream.Close()
}

func (c *interConn) LocalAddr() net.Addr {
	return c.local
}

func (c *interConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *interConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *interConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *interConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

type InterConn struct {
	local  net.Addr
	remote net.Addr

	id     uint32
	ch     chan []byte
	time   time.Time
	mutex  sync.Mutex
	closed bool

	write func(p []byte) error
	close func()
	user  *protocol.MemoryUser
}

func (i *InterConn) User() *protocol.MemoryUser {
	return i.user
}

func (c *InterConn) Time() time.Time {
	c.mutex.Lock()
	v := c.time
	c.mutex.Unlock()
	return v
}

func (c *InterConn) Update() {
	c.mutex.Lock()
	c.time = time.Now()
	c.mutex.Unlock()
}

func (c *InterConn) Read(p []byte) (int, error) {
	b, ok := <-c.ch
	if !ok {
		return 0, io.EOF
	}
	if len(p) < len(b) {
		return 0, io.ErrShortBuffer
	}
	c.Update()
	return copy(p, b), nil
}

func (c *InterConn) Write(p []byte) (int, error) {
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	binary.BigEndian.PutUint32(p, c.id)
	if err := c.write(p); err != nil {
		return 0, err
	}
	c.Update()
	return len(p), nil
}

func (c *InterConn) Close() error {
	c.close()
	return nil
}

func (c *InterConn) LocalAddr() net.Addr {
	return c.local
}

func (c *InterConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *InterConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *InterConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *InterConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type udpSessionManager struct {
	sync.RWMutex

	conn   *quic.Conn
	m      map[uint32]*InterConn
	next   uint32
	closed bool

	addConn        internet.ConnHandler
	udpIdleTimeout time.Duration
	user           *protocol.MemoryUser
}

func (m *udpSessionManager) close(udpConn *InterConn) {
	if !udpConn.closed {
		udpConn.closed = true
		close(udpConn.ch)
		delete(m.m, udpConn.id)
	}
}

func (m *udpSessionManager) clean() {
	ticker := time.NewTicker(idleCleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		if m.closed {
			return
		}

		m.RLock()
		now := time.Now()
		timeoutConn := make([]*InterConn, 0, len(m.m))
		for _, udpConn := range m.m {
			if now.Sub(udpConn.Time()) > m.udpIdleTimeout {
				timeoutConn = append(timeoutConn, udpConn)
			}
		}
		m.RUnlock()

		for _, udpConn := range timeoutConn {
			m.Lock()
			m.close(udpConn)
			m.Unlock()
		}
	}
}

func (m *udpSessionManager) run() {
	for {
		d, err := m.conn.ReceiveDatagram(context.Background())
		if err != nil {
			break
		}

		if len(d) < 4 {
			continue
		}
		id := binary.BigEndian.Uint32(d[:4])

		m.feed(id, d)
	}

	m.Lock()
	defer m.Unlock()

	m.closed = true

	for _, udpConn := range m.m {
		m.close(udpConn)
	}
}

func (m *udpSessionManager) udp() (*InterConn, error) {
	m.Lock()
	defer m.Unlock()

	if m.closed {
		return nil, errors.New("closed")
	}

	udpConn := &InterConn{
		local:  m.conn.LocalAddr(),
		remote: m.conn.RemoteAddr(),

		id: m.next,
		ch: make(chan []byte, udpMessageChanSize),
	}
	udpConn.write = m.conn.SendDatagram
	udpConn.close = func() {
		m.Lock()
		m.close(udpConn)
		m.Unlock()
	}
	m.m[m.next] = udpConn
	m.next++

	return udpConn, nil
}

func (m *udpSessionManager) feed(id uint32, d []byte) {
	m.RLock()
	udpConn, ok := m.m[id]
	if ok {
		select {
		case udpConn.ch <- d:
		default:
		}
		m.RUnlock()
		return
	}
	m.RUnlock()

	if m.addConn == nil {
		return
	}

	m.Lock()
	defer m.Unlock()

	udpConn, ok = m.m[id]
	if !ok {
		udpConn = &InterConn{
			local:  m.conn.LocalAddr(),
			remote: m.conn.RemoteAddr(),

			id:   id,
			ch:   make(chan []byte, udpMessageChanSize),
			time: time.Now(),
		}
		udpConn.write = m.conn.SendDatagram
		udpConn.close = func() {
			m.Lock()
			m.close(udpConn)
			m.Unlock()
		}
		udpConn.user = m.user
		m.m[id] = udpConn
		m.addConn(udpConn)
	}

	select {
	case udpConn.ch <- d:
	default:
	}
}
