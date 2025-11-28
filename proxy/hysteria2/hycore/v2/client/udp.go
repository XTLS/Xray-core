package client

import (
	"errors"
	"io"
	"math/rand"
	"sync"

	"github.com/apernet/quic-go"

	coreErrs "github.com/xtls/xray-core/proxy/hysteria2/hycore/v2/errors"
	"github.com/xtls/xray-core/proxy/hysteria2/hycore/v2/internal/frag"
	"github.com/xtls/xray-core/proxy/hysteria2/hycore/v2/internal/protocol"
)

const (
	udpMessageChanSize = 1024
)

type udpIO interface {
	ReceiveMessage() (*protocol.UDPMessage, error)
	SendMessage([]byte, *protocol.UDPMessage) error
}

type udpConn struct {
	ID        uint32
	D         *frag.Defragger
	ReceiveCh chan *protocol.UDPMessage
	SendBuf   []byte
	SendFunc  func([]byte, *protocol.UDPMessage) error
	CloseFunc func()
	Closed    bool
}

func (u *udpConn) Receive() ([]byte, string, error) {
	for {
		msg := <-u.ReceiveCh
		if msg == nil {
			// Closed
			return nil, "", io.EOF
		}
		dfMsg := u.D.Feed(msg)
		if dfMsg == nil {
			// Incomplete message, wait for more
			continue
		}
		return dfMsg.Data, dfMsg.Addr, nil
	}
}

// Send is not thread-safe, as it uses a shared SendBuf.
func (u *udpConn) Send(data []byte, addr string) error {
	// Try no frag first
	msg := &protocol.UDPMessage{
		SessionID: u.ID,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      addr,
		Data:      data,
	}
	err := u.SendFunc(u.SendBuf, msg)
	var errTooLarge *quic.DatagramTooLargeError
	if errors.As(err, &errTooLarge) {
		// Message too large, try fragmentation
		msg.PacketID = uint16(rand.Intn(0xFFFF)) + 1
		fMsgs := frag.FragUDPMessage(msg, int(errTooLarge.MaxDatagramPayloadSize))
		for _, fMsg := range fMsgs {
			err := u.SendFunc(u.SendBuf, &fMsg)
			if err != nil {
				return err
			}
		}
		return nil
	} else {
		return err
	}
}

func (u *udpConn) Close() error {
	u.CloseFunc()
	return nil
}

type udpSessionManager struct {
	io udpIO

	mutex  sync.RWMutex
	m      map[uint32]*udpConn
	nextID uint32

	closed bool
}

func newUDPSessionManager(io udpIO) *udpSessionManager {
	m := &udpSessionManager{
		io:     io,
		m:      make(map[uint32]*udpConn),
		nextID: 1,
	}
	go m.run()
	return m
}

func (m *udpSessionManager) run() error {
	defer m.closeCleanup()
	for {
		msg, err := m.io.ReceiveMessage()
		if err != nil {
			return err
		}
		m.feed(msg)
	}
}

func (m *udpSessionManager) closeCleanup() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, conn := range m.m {
		m.close(conn)
	}
	m.closed = true
}

func (m *udpSessionManager) feed(msg *protocol.UDPMessage) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	conn, ok := m.m[msg.SessionID]
	if !ok {
		// Ignore message from unknown session
		return
	}

	select {
	case conn.ReceiveCh <- msg:
		// OK
	default:
		// Channel full, drop the message
	}
}

// NewUDP creates a new UDP session.
func (m *udpSessionManager) NewUDP() (HyUDPConn, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.closed {
		return nil, coreErrs.ClosedError{}
	}

	id := m.nextID
	m.nextID++

	conn := &udpConn{
		ID:        id,
		D:         &frag.Defragger{},
		ReceiveCh: make(chan *protocol.UDPMessage, udpMessageChanSize),
		SendBuf:   make([]byte, protocol.MaxUDPSize),
		SendFunc:  m.io.SendMessage,
	}
	conn.CloseFunc = func() {
		m.mutex.Lock()
		defer m.mutex.Unlock()
		m.close(conn)
	}
	m.m[id] = conn

	return conn, nil
}

func (m *udpSessionManager) close(conn *udpConn) {
	if !conn.Closed {
		conn.Closed = true
		close(conn.ReceiveCh)
		delete(m.m, conn.ID)
	}
}

func (m *udpSessionManager) Count() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.m)
}
