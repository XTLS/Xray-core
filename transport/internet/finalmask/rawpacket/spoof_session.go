package rawpacket

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

type RelaySession struct {
	ID         [8]byte
	ClientIP   netip.Addr
	ClientPort uint16
	TargetConn net.Conn
	crypto     *frameCrypto
	tcp        *TCPSimState
	LastSeen   time.Time
	mu         sync.Mutex
	closed     bool
}

type SessionManager struct {
	sessions map[[8]byte]*RelaySession
	mu       sync.Mutex
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[[8]byte]*RelaySession),
	}
}

func (sm *SessionManager) Add(id [8]byte, clientIP netip.Addr, clientPort uint16, targetConn net.Conn, crypto *frameCrypto, tcp *TCPSimState) *RelaySession {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	s := &RelaySession{
		ID:         id,
		ClientIP:   clientIP,
		ClientPort: clientPort,
		TargetConn: targetConn,
		crypto:     crypto,
		tcp:        tcp,
		LastSeen:   time.Now(),
	}
	sm.sessions[id] = s
	return s
}

func (sm *SessionManager) Get(id [8]byte) *RelaySession {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.sessions[id]
}

// Remove is idempotent: it closes the target connection, marks the
// session closed and drops it from the map.
func (sm *SessionManager) Remove(id [8]byte) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if s, ok := sm.sessions[id]; ok {
		s.closed = true
		s.TargetConn.Close()
		delete(sm.sessions, id)
	}
}

func (sm *SessionManager) All() []*RelaySession {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	out := make([]*RelaySession, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		out = append(out, s)
	}
	return out
}

func (sm *SessionManager) Close() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for _, s := range sm.sessions {
		s.closed = true
		s.TargetConn.Close()
	}
	clear(sm.sessions)
}
