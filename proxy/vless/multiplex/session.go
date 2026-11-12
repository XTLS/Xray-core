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
	return m.allocate(Strategy, input, output, transferType)
}

func (m *SessionManager) allocate(Strategy *ClientStrategy, input buf.Reader, output buf.Writer, transferType protocol.TransferType) *Session {
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
	input          buf.Reader
	output         buf.Writer
	parent         *SessionManager
	ID             uint16
	transferType   protocol.TransferType
	closed         bool
	failed         bool // immutable winning close reason, guarded by parent
	done           *done.Instance
	flow           *inboundFlow
	sender         *carrier
	packetProducer *childResponse // client producer, set before publication
}

// writePayload transfers parser custody to the admitted native flow.
func (s *Session) writePayload(data buf.MultiBuffer) error {
	if s.flow == nil {
		return s.output.WriteMultiBuffer(data)
	}
	err := s.flow.accept(data, s)
	if err != nil {
		buf.ReleaseMulti(data)
	}
	return err
}

// Close closes all resources associated with this session.
func (s *Session) Close() error { s.close(true); return nil }

// close atomically chooses logical completion and its reason, then notifies the
// response owner outside the registry lock. It never waits for physical output.
func (s *Session) close(failed bool) { s.closeOwned(failed, nil) }
func (s *Session) closeOwned(failed bool, owner *inboundFlow) {
	s.parent.Lock()
	if s.closed || (owner != nil && s.flow != owner) {
		s.parent.Unlock()
		return
	}
	x := s.flow
	if x != nil {
		if x.GlobalID != [8]byte{} {
			XUDPManager.Lock()
		}
		x.access.Lock()
		if owner != nil && x.Status == Initializing {
			x.access.Unlock()
			if x.GlobalID != [8]byte{} {
				XUDPManager.Unlock()
			}
			s.parent.Unlock()
			return
		}
		failed = failed || x.responseErr == io.ErrClosedPipe
	}
	s.closed, s.failed = true, failed
	if x == nil && s.parent.sessions[s.ID] == s {
		delete(s.parent.sessions, s.ID)
	}
	if s.done != nil {
		s.done.Close()
	}
	if x != nil {
		if x.binding == s {
			x.binding = nil
			if x.GlobalID == [8]byte{} {
				if x.requestErr == nil {
					x.requestErr = io.EOF
				}
				x.responseErr = io.ErrClosedPipe
				x.response = buf.ReleaseMulti(x.response)
			} else if x.Status == Active {
				x.Expire, x.Status = time.Now().Add(time.Minute), Expiring
			}
			x.notify()
		}
		x.access.Unlock()
		if x.GlobalID != [8]byte{} {
			XUDPManager.Unlock()
		}
	}
	s.parent.Unlock()
	if s.flow == nil {
		common.Interrupt(s.input)
		common.Close(s.output)
	}

	if s.packetProducer != nil {
		s.packetProducer.end(failed)
	}

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

var XUDPManager struct {
	sync.Mutex
	Map map[[8]byte]*inboundFlow
}

func init() {
	XUDPManager.Map = make(map[[8]byte]*inboundFlow)
	go func() {
		for {
			time.Sleep(time.Minute)
			now := time.Now()
			var expired []*inboundFlow
			XUDPManager.Lock()
			for id, x := range XUDPManager.Map {
				if x.Status == Expiring && now.After(x.Expire) {
					expired = append(expired, x)
					delete(XUDPManager.Map, id)
					errors.LogDebug(context.Background(), "XUDP del ", id)
				}
			}
			XUDPManager.Unlock()
			for _, x := range expired {
				x.expire()
			}
		}
	}()
}
