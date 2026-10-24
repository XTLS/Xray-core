package inbound

import (
	"context"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/protocol"
)

type userConn struct {
	conn   io.Closer
	cancel context.CancelFunc
}

// userConns tracks live connections per authenticated user, keyed by the exact
// MemoryUser so that a removed-then-re-added email does not share entries.
type userConns struct {
	sync.Mutex
	byUser map[*protocol.MemoryUser]map[*userConn]struct{}
}

// track registers a connection of u and returns the func that forgets it.
func (t *userConns) track(u *protocol.MemoryUser, conn io.Closer, cancel context.CancelFunc) func() {
	c := &userConn{conn: conn, cancel: cancel}
	t.Lock()
	if t.byUser == nil {
		t.byUser = make(map[*protocol.MemoryUser]map[*userConn]struct{})
	}
	set := t.byUser[u]
	if set == nil {
		set = make(map[*userConn]struct{})
		t.byUser[u] = set
	}
	set[c] = struct{}{}
	t.Unlock()
	return func() {
		t.Lock()
		if set := t.byUser[u]; set != nil {
			delete(set, c)
			if len(set) == 0 {
				delete(t.byUser, u)
			}
		}
		t.Unlock()
	}
}

// closeAll closes every live connection of u, including Mux sub-connections carried by them.
func (t *userConns) closeAll(u *protocol.MemoryUser) {
	t.Lock()
	set := t.byUser[u]
	delete(t.byUser, u)
	t.Unlock()
	for c := range set {
		c.cancel()
		go c.conn.Close() // a TLS close_notify may block on a stalled peer, keep RemoveUser fast
	}
}
