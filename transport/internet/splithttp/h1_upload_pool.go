package splithttp

import (
	"sync"
	"time"
)

// h1UploadPool owns HTTP/1.1 upload connections. sync.Pool is not suitable
// here because it can discard values without closing their sockets.
type h1UploadPool struct {
	mu          sync.Mutex
	idleTimeout time.Duration
	conns       map[*H1Conn]*h1UploadPoolEntry
	closed      bool
}

type h1UploadPoolEntry struct {
	idle       bool
	generation uint64
	timer      *time.Timer
}

func newH1UploadPool(idleTimeout time.Duration) *h1UploadPool {
	return &h1UploadPool{
		idleTimeout: idleTimeout,
		conns:       make(map[*H1Conn]*h1UploadPoolEntry),
	}
}

func (p *h1UploadPool) Get() *H1Conn {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	for conn, entry := range p.conns {
		if !entry.idle {
			continue
		}
		entry.idle = false
		entry.generation++
		entry.timer.Stop()
		return conn
	}

	return nil
}

func (p *h1UploadPool) Add(conn *H1Conn) bool {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		conn.Close()
		return false
	}
	p.conns[conn] = &h1UploadPoolEntry{}
	p.mu.Unlock()
	return true
}

func (p *h1UploadPool) Release(conn *H1Conn) {
	p.mu.Lock()
	entry, found := p.conns[conn]
	if p.closed || !found {
		p.mu.Unlock()
		conn.Close()
		return
	}

	if entry.timer != nil {
		entry.timer.Stop()
	}
	entry.idle = true
	entry.generation++
	generation := entry.generation
	entry.timer = time.AfterFunc(p.idleTimeout, func() {
		p.closeIdle(conn, generation)
	})
	p.mu.Unlock()
}

func (p *h1UploadPool) Discard(conn *H1Conn) {
	p.mu.Lock()
	entry, found := p.conns[conn]
	if found {
		delete(p.conns, conn)
		if entry.timer != nil {
			entry.timer.Stop()
		}
	}
	p.mu.Unlock()

	conn.Close()
}

func (p *h1UploadPool) closeIdle(conn *H1Conn, generation uint64) {
	p.mu.Lock()
	entry, found := p.conns[conn]
	if !found || !entry.idle || entry.generation != generation {
		p.mu.Unlock()
		return
	}
	delete(p.conns, conn)
	p.mu.Unlock()

	conn.Close()
}

func (p *h1UploadPool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true

	conns := make([]*H1Conn, 0, len(p.conns))
	for conn, entry := range p.conns {
		if entry.timer != nil {
			entry.timer.Stop()
		}
		conns = append(conns, conn)
	}
	clear(p.conns)
	p.mu.Unlock()

	for _, conn := range conns {
		conn.Close()
	}

	return nil
}
