package inbound

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestUDPWorkerCleanIdleTimeout(t *testing.T) {
	newConn := func(idle time.Duration) *udpConn {
		pReader, pWriter := pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(16*1024))
		c := &udpConn{reader: pReader, writer: pWriter, done: done.New()}
		atomic.StoreInt64(&c.lastActivityTime, time.Now().Add(-idle).Unix())
		return c
	}
	id := func(port net.Port) connID {
		return connID{src: net.UDPDestination(net.LocalHostIP, port)}
	}

	cases := []struct {
		name        string
		idleTimeout time.Duration
		idle        time.Duration
		closed      bool
	}{
		{"default keeps 100 s", 0, 100 * time.Second, false},
		{"default closes 200 s", 0, 200 * time.Second, true},
		{"600 s keeps 300 s", 600 * time.Second, 300 * time.Second, false},
		{"600 s closes 700 s", 600 * time.Second, 700 * time.Second, true},
		{"30 s closes 60 s", 30 * time.Second, 60 * time.Second, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := newConn(c.idle)
			w := &udpWorker{
				activeConn:  map[connID]*udpConn{id(1): conn, id(2): newConn(0)},
				idleTimeout: c.idleTimeout,
			}
			if err := w.clean(); err != nil {
				t.Fatal(err)
			}
			_, found := w.activeConn[id(1)]
			if found == c.closed || conn.done.Done() != c.closed {
				t.Errorf("closed: want %v, got found=%v done=%v", c.closed, found, conn.done.Done())
			}
			if _, found := w.activeConn[id(2)]; !found {
				t.Error("an active session was closed")
			}
		})
	}
}
