package rawpacket

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

type RelaySession struct {
	ClientIP   netip.Addr
	ClientPort uint16
	ServerAddr netip.Addr
	TargetConn net.Conn
	LastSeen   time.Time
	mu         sync.Mutex
	closed     bool
}

type SessionManager struct {
	sessions map[sessionKey]*RelaySession
	mu       sync.Mutex
}

type sessionKey struct {
	ip   [16]byte
	port uint16
}

func addrToKey(ip netip.Addr) [16]byte {
	var out [16]byte
	b := ip.As16()
	copy(out[:], b[:])
	return out
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[sessionKey]*RelaySession),
	}
}

func (sm *SessionManager) Add(clientIP netip.Addr, clientPort uint16, targetConn net.Conn, serverAddr netip.Addr) *RelaySession {
	key := sessionKey{ip: addrToKey(clientIP), port: clientPort}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	s := &RelaySession{
		ClientIP:   clientIP,
		ClientPort: clientPort,
		ServerAddr: serverAddr,
		TargetConn: targetConn,
		LastSeen:   time.Now(),
	}
	sm.sessions[key] = s
	return s
}

func (sm *SessionManager) Get(clientIP netip.Addr, clientPort uint16) *RelaySession {
	key := sessionKey{ip: addrToKey(clientIP), port: clientPort}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	s, ok := sm.sessions[key]
	if !ok {
		return nil
	}
	s.LastSeen = time.Now()
	return s
}

func (sm *SessionManager) Remove(clientIP netip.Addr, clientPort uint16) {
	key := sessionKey{ip: addrToKey(clientIP), port: clientPort}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if s, ok := sm.sessions[key]; ok {
		s.closed = true
		s.TargetConn.Close()
		delete(sm.sessions, key)
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
