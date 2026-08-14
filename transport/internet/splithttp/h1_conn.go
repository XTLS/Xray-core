package splithttp

import (
	"bufio"
	"net"
	"sync"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

type H1Conn struct {
	UnreadedResponsesCount int
	RespBufReader          *bufio.Reader
	net.Conn

	idleTimeout time.Duration
	mu          sync.Mutex
	idleTimer   *time.Timer
}

func NewH1Conn(conn net.Conn) *H1Conn {
	return &H1Conn{
		RespBufReader: bufio.NewReader(conn),
		Conn:          conn,
		idleTimeout:   xnet.ConnIdleTimeout,
	}
}

// SetIdle starts (or restarts) the idle timer. When it fires, the
// underlying connection is closed, bounding the lifetime of pooled
// HTTP/1.1 upload connections that would otherwise stay open until
// the GC collects the pool.
func (h *H1Conn) SetIdle() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.idleTimeout <= 0 {
		return
	}
	if h.idleTimer != nil {
		h.idleTimer.Stop()
	}
	h.idleTimer = time.AfterFunc(h.idleTimeout, func() {
		h.Conn.Close()
	})
}

// ResetIdle cancels the idle timer, e.g. while the connection is back in use.
func (h *H1Conn) ResetIdle() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.idleTimer != nil {
		h.idleTimer.Stop()
		h.idleTimer = nil
	}
}

func (h *H1Conn) Close() error {
	h.ResetIdle()
	return h.Conn.Close()
}
