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

func (i *interConn) User() *protocol.MemoryUser {
	return i.user
}

func (i *interConn) Read(b []byte) (int, error) {
	return i.stream.Read(b)
}

func (i *interConn) Write(b []byte) (int, error) {
	if i.client {
		i.client = false
		if _, err := i.stream.Write(append(quicvarint.Append(nil, FrameTypeTCPRequest), b...)); err != nil {
			return 0, err
		}
		return len(b), nil
	}

	return i.stream.Write(b)
}

func (i *interConn) Close() error {
	i.stream.CancelRead(0)
	return i.stream.Close()
}

func (i *interConn) LocalAddr() net.Addr {
	return i.local
}

func (i *interConn) RemoteAddr() net.Addr {
	return i.remote
}

func (i *interConn) SetDeadline(t time.Time) error {
	return i.stream.SetDeadline(t)
}

func (i *interConn) SetReadDeadline(t time.Time) error {
	return i.stream.SetReadDeadline(t)
}

func (i *interConn) SetWriteDeadline(t time.Time) error {
	return i.stream.SetWriteDeadline(t)
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

func (i *InterConn) Time() time.Time {
	i.mutex.Lock()
	v := i.time
	i.mutex.Unlock()
	return v
}

func (i *InterConn) Update() {
	i.mutex.Lock()
	i.time = time.Now()
	i.mutex.Unlock()
}

func (i *InterConn) Read(p []byte) (int, error) {
	b, ok := <-i.ch
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, b)
	if n != len(b) {
		return 0, io.ErrShortBuffer
	}
	i.Update()
	return n, nil
}

func (i *InterConn) Write(p []byte) (int, error) {
	if i.closed {
		return 0, io.ErrClosedPipe
	}
	i.Update()
	binary.BigEndian.PutUint32(p, i.id)
	if err := i.write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (i *InterConn) Close() error {
	i.close()
	return nil
}

func (i *InterConn) LocalAddr() net.Addr {
	return i.local
}

func (i *InterConn) RemoteAddr() net.Addr {
	return i.remote
}

func (i *InterConn) SetDeadline(t time.Time) error {
	return nil
}

func (i *InterConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (i *InterConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type udpSessionManager struct {
	conn   *quic.Conn
	m      map[uint32]*InterConn
	next   uint32
	closed bool
	mutex  sync.RWMutex

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

		m.mutex.RLock()
		now := time.Now()
		timeoutConn := make([]*InterConn, 0, len(m.m))
		for _, udpConn := range m.m {
			if now.Sub(udpConn.Time()) > m.udpIdleTimeout {
				timeoutConn = append(timeoutConn, udpConn)
			}
		}
		m.mutex.RUnlock()

		for _, udpConn := range timeoutConn {
			m.mutex.Lock()
			m.close(udpConn)
			m.mutex.Unlock()
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

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.closed = true

	for _, udpConn := range m.m {
		m.close(udpConn)
	}
}

func (m *udpSessionManager) udp() (*InterConn, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

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
		m.mutex.Lock()
		m.close(udpConn)
		m.mutex.Unlock()
	}
	m.m[m.next] = udpConn
	m.next++

	return udpConn, nil
}

func (m *udpSessionManager) feed(id uint32, d []byte) {
	m.mutex.RLock()
	udpConn, ok := m.m[id]
	if ok {
		select {
		case udpConn.ch <- d:
		default:
		}
		m.mutex.RUnlock()
		return
	}
	m.mutex.RUnlock()

	if m.addConn == nil {
		return
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

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
			m.mutex.Lock()
			m.close(udpConn)
			m.mutex.Unlock()
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
