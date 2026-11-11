package multiplex

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/pipe"
)

type SessionManager struct {
	sync.RWMutex
	sessions map[uint16]*Session
	count    uint16
	closed   bool
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		count:    0,
		sessions: make(map[uint16]*Session, 16),
	}
}

func (m *SessionManager) Closed() bool {
	m.RLock()
	defer m.RUnlock()

	return m.closed
}

func (m *SessionManager) Size() int {
	m.RLock()
	defer m.RUnlock()

	return m.sizeLocked()
}

// Closed server entries drain in-flight ingress without counting as activity.
func (m *SessionManager) sizeLocked() int {
	active := 0
	for _, s := range m.sessions {
		if !s.closed {
			active++
		}
	}
	return active
}

func (m *SessionManager) Count() int {
	m.RLock()
	defer m.RUnlock()

	return int(m.count)
}

func (m *SessionManager) Allocate(Strategy *ClientStrategy, input buf.Reader, output buf.Writer, transferType protocol.TransferType) *Session {
	m.Lock()
	defer m.Unlock()

	MaxConcurrency := int(Strategy.MaxConcurrency)
	MaxConnection := uint16(Strategy.MaxConnection)

	if m.closed || (MaxConcurrency > 0 && len(m.sessions) >= MaxConcurrency) || (MaxConnection > 0 && m.count >= MaxConnection) {
		return nil
	}

	m.count++
	s := &Session{
		transferType: transferType,
		input:        input,
		output:       output,
		ID:           m.count,
		parent:       m,
		done:         done.New(),
	}
	m.sessions[s.ID] = s
	return s
}

func (m *SessionManager) Add(s *Session) bool {
	m.Lock()
	defer m.Unlock()

	if m.closed {
		return false
	}

	m.count++
	m.sessions[s.ID] = s
	return true
}

func (m *SessionManager) Get(id uint16) (*Session, bool) {
	m.RLock()
	defer m.RUnlock()

	if m.closed {
		return nil, false
	}

	s, found := m.sessions[id]
	return s, found
}

func (m *SessionManager) CloseIfNoSessionAndIdle(checkSize int, checkCount int) bool {
	m.Lock()
	defer m.Unlock()

	if m.closed {
		return true
	}

	if m.sizeLocked() != 0 || checkSize != 0 || checkCount != int(m.count) {
		return false
	}

	m.closed = true

	m.sessions = nil
	return true
}

func (m *SessionManager) Close() error {
	m.Lock()
	if m.closed {
		m.Unlock()
		return nil
	}
	m.closed = true
	sessions := m.sessions
	m.sessions = nil
	m.Unlock()
	for _, current := range sessions {
		current.Close()
	}
	return nil
}

// Session represents a client connection in a Mux connection.
type Session struct {
	input        buf.Reader
	output       buf.Writer
	parent       *SessionManager
	ID           uint16
	transferType protocol.TransferType
	closed       bool
	keepUntilEnd bool // server ingress identity survives logical close until END returns
	done         *done.Instance
	XUDP         *XUDP
	onClose      func(bool) // immutable direct response completion, set before admission
}

// ReadMultiBuffer keeps retained XUDP reads inside their admitted generation.
func (s *Session) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if s.XUDP == nil {
		return s.input.ReadMultiBuffer()
	}
	s.XUDP.readAccess.Lock()
	defer s.XUDP.readAccess.Unlock()
	if s.done.Done() {
		return nil, io.EOF
	}
	return s.input.ReadMultiBuffer()
}

// Close closes all resources associated with this session.
func (s *Session) Close() error { s.close(true); return nil }

// close atomically chooses logical completion and its reason, then notifies the
// response owner outside the registry lock. It never waits for physical output.
func (s *Session) close(failed bool) {
	s.parent.Lock()
	if s.closed {
		s.parent.Unlock()
		return
	}
	s.closed = true
	if s.done != nil {
		s.done.Close()
	}
	if !s.keepUntilEnd && s.parent.sessions[s.ID] == s {
		delete(s.parent.sessions, s.ID)
	}
	if s.XUDP == nil {
		s.parent.Unlock()
		common.Interrupt(s.input)
		common.Close(s.output)
		if s.onClose != nil {
			s.onClose(failed)
		}
		return
	}
	// Retained XUDP rebind still joins detach through the parent lock.
	defer s.parent.Unlock()
	// Wake and join only an admitted read, never a carrier DATA or END write.
	input := s.input.(*pipe.Reader)
	input.ReturnAnError(io.EOF)
	s.XUDP.readAccess.Lock()
	input.Recover()
	s.XUDP.readAccess.Unlock()
	XUDPManager.Lock()
	if s.XUDP.Status == Active {
		s.XUDP.Expire = time.Now().Add(time.Minute)
		s.XUDP.Status = Expiring
		errors.LogDebug(context.Background(), "XUDP put ", s.XUDP.GlobalID)
	}
	XUDPManager.Unlock()
	return
}

// endWritten releases only this ingress identity; the peer may already have
// reused its ID after observing END but before the physical write returned.
func (s *Session) endWritten() {
	s.parent.Lock()
	defer s.parent.Unlock()
	if s.parent.sessions[s.ID] == s {
		delete(s.parent.sessions, s.ID)
	}
}

const (
	Initializing = 0
	Active       = 1
	Expiring     = 2
)

type XUDP struct {
	readAccess sync.Mutex
	GlobalID   [8]byte
	Status     uint64
	Expire     time.Time
	Mux        *Session
}

func (x *XUDP) Interrupt() {
	common.Interrupt(x.Mux.input)
	common.Close(x.Mux.output)
}

var XUDPManager struct {
	sync.Mutex
	Map map[[8]byte]*XUDP
}

func init() {
	XUDPManager.Map = make(map[[8]byte]*XUDP)
	go func() {
		for {
			time.Sleep(time.Minute)
			now := time.Now()
			XUDPManager.Lock()
			for id, x := range XUDPManager.Map {
				if x.Status == Expiring && now.After(x.Expire) {
					x.Interrupt()
					delete(XUDPManager.Map, id)
					errors.LogDebug(context.Background(), "XUDP del ", id)
				}
			}
			XUDPManager.Unlock()
		}
	}()
}
