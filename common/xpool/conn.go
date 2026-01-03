package xpool

import (
	"io"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

type GatewayConn struct {
	io.ReadWriteCloser
	LastActive time.Time
	pool       *ConnectionPool
	done       chan struct{}
}

func NewGatewayConn(rwc io.ReadWriteCloser, pool *ConnectionPool) *GatewayConn {
	c := &GatewayConn{
		ReadWriteCloser: rwc,
		LastActive:      time.Now(),
		pool:            pool,
		done:            make(chan struct{}),
	}
	go c.readLoop()
	return c
}

func (c *GatewayConn) Done() <-chan struct{} {
	return c.done
}

func (c *GatewayConn) readLoop() {
	defer close(c.done)
	reader := NewSegmentReader(c)
	for {
		seg, err := reader.ReadSegment()
		if err != nil {
			errors.LogInfoInner(nil, err, "gateway connection read error")
			c.pool.Remove(0, c)
			return
		}
		c.pool.OnSegment(c, seg)
	}
}
