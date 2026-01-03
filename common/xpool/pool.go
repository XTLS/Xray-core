package xpool

import (
	"container/list"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

type PoolConfig struct {
	MaxIdle     int
	IdleTimeout time.Duration
}

type ConnectionPool struct {
	idle      *list.List                // Front=Oldest, Back=Newest
	idleMap   map[*GatewayConn]*list.Element
	active    map[uint32]*GatewayConn   // SessionID -> Conn
	connToSID map[*GatewayConn]uint32   // Conn -> SessionID
	sessions     map[uint32]Session      // SessionID -> Session
	config       PoolConfig
	mu           sync.Mutex
	dialer       func() (io.ReadWriteCloser, error)
	onNewSession func(conn *GatewayConn, seg *Segment) Session
}

func NewConnectionPool(config PoolConfig, dialer func() (io.ReadWriteCloser, error)) *ConnectionPool {
	return &ConnectionPool{
		idle:      list.New(),
		idleMap:   make(map[*GatewayConn]*list.Element),
		active:    make(map[uint32]*GatewayConn),
		connToSID: make(map[*GatewayConn]uint32),
		sessions:  make(map[uint32]Session),
		config:    config,
		dialer:    dialer,
	}
}

func (p *ConnectionPool) SetNewSessionCallback(cb func(conn *GatewayConn, seg *Segment) Session) {
	p.onNewSession = cb
}

func (p *ConnectionPool) RegisterSession(s Session) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sessions[s.GetID()] = s
}

func (p *ConnectionPool) UnregisterSession(sid uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.sessions, sid)
}

func (p *ConnectionPool) Get(sid uint32) (*GatewayConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if elem := p.idle.Front(); elem != nil {
		conn := elem.Value.(*GatewayConn)
		p.idle.Remove(elem)
		delete(p.idleMap, conn)

		p.active[sid] = conn
		p.connToSID[conn] = sid
		errors.LogDebug(nil, "reusing idle connection for session ", sid)
		return conn, nil
	}

	p.mu.Unlock()
	rwc, err := p.dialer()
	p.mu.Lock()

	if err != nil {
		return nil, err
	}

	conn := NewGatewayConn(rwc, p)
	p.active[sid] = conn
	p.connToSID[conn] = sid
	errors.LogDebug(nil, "dialed new connection for session ", sid)
	return conn, nil
}

func (p *ConnectionPool) Return(sid uint32, conn *GatewayConn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if c, ok := p.active[sid]; ok && c == conn {
		delete(p.active, sid)
		delete(p.connToSID, conn)
	}

	conn.LastActive = time.Now()

	if p.idle.Len() >= p.config.MaxIdle {
		if oldest := p.idle.Front(); oldest != nil {
			oldConn := oldest.Value.(*GatewayConn)
			p.idle.Remove(oldest)
			delete(p.idleMap, oldConn)
			oldConn.Close()
		}
	}

	elem := p.idle.PushBack(conn)
	p.idleMap[conn] = elem
}

func (p *ConnectionPool) Remove(sid uint32, conn *GatewayConn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if sid == 0 {
		if s, ok := p.connToSID[conn]; ok {
			sid = s
		}
	}

	errors.LogDebug(nil, "removing connection for session ", sid)

	session := p.sessions[sid]
	if session != nil {
		p.mu.Unlock()
		if s, ok := session.(interface{ OnConnectionClose(*GatewayConn) }); ok {
			s.OnConnectionClose(conn)
		}
		p.mu.Lock()
	}

	if c, ok := p.active[sid]; ok && c == conn {
		delete(p.active, sid)
		delete(p.connToSID, conn)
	}
	if elem, ok := p.idleMap[conn]; ok {
		p.idle.Remove(elem)
		delete(p.idleMap, conn)
	}
	conn.Close()
}

func (p *ConnectionPool) CleanupExpired() {
	p.mu.Lock()
	defer p.mu.Unlock()

	errors.LogDebug(nil, "cleaning up expired connections")

	now := time.Now()
	for elem := p.idle.Front(); elem != nil; {
		conn := elem.Value.(*GatewayConn)
		if now.Sub(conn.LastActive) <= p.config.IdleTimeout {
			break
		}
		next := elem.Next()
		p.idle.Remove(elem)
		delete(p.idleMap, conn)
		conn.Close()
		elem = next
	}
}

func (p *ConnectionPool) OnSegment(conn *GatewayConn, seg *Segment) {
	p.mu.Lock()

	conn.LastActive = time.Now()

	sid := seg.SID
	if sid == 0 {
		if s, ok := p.connToSID[conn]; ok {
			sid = s
		}
	}

	session := p.sessions[sid]
	p.mu.Unlock()

	if session != nil {
		session.OnSegment(conn, seg)
	} else {
		if p.onNewSession != nil {
			session = p.onNewSession(conn, seg)
			if session != nil {
				p.mu.Lock()
				p.sessions[session.GetID()] = session
				p.mu.Unlock()
				session.OnSegment(conn, seg)
				return
			}
		}

		if seg.Payload != nil {
			seg.Payload.Release()
		}
	}
}
