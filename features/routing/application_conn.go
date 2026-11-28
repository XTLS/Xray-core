package routing

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
)

// DialApplication creates the application endpoint of a routed connection.
// Its writes and received data are owned at this boundary. The dispatcher is
// given the endpoints directly, without a separate forwarding worker.
func DialApplication(ctx context.Context, dispatcher Dispatcher, dest net.Destination) (net.Conn, error) {
	if !dest.IsValid() {
		return nil, errors.New("invalid destination")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	routeCtx, cancel := context.WithCancel(ctx)
	conn := &applicationConn{
		parent: ctx,
		cancel: cancel,
		limit:  int64(policy.BufferPolicyFromContext(ctx).PerConnection),
		packet: dest.Network != net.Network_TCP,
	}
	stopWatch := context.AfterFunc(ctx, func() {
		conn.abort(ctx.Err())
	})
	go func() {
		defer cancel()
		defer stopWatch()
		if routeCtx.Err() != nil {
			if err := ctx.Err(); err != nil {
				conn.abort(err)
			}
			return
		}
		err := dispatcher.DispatchLink(routeCtx, dest, &transport.Link{
			Reader: applicationInput{conn},
			Writer: applicationOutput{conn},
		})
		if ctx.Err() != nil {
			conn.abort(ctx.Err())
			return
		}
		conn.finish(err)
	}()
	return conn, nil
}

type applicationConn struct {
	mu      sync.Mutex
	changed chan struct{}
	parent  context.Context
	cancel  context.CancelFunc
	limit   int64
	packet  bool
	closed  bool

	sent          buf.MultiBuffer
	sentBytes     int64
	accepted      bool
	sendErr       error
	writeDeadline time.Time
	attempted     int64
	bound         bool
	uplink        stats.Counter
	nested        []stats.Counter

	received     buf.MultiBuffer
	receiveBytes int64
	readRest     buf.MultiBuffer
	receiveErr   error
	readDeadline time.Time
}

// wait returns with mu held, so each caller retries against current state and
// the current deadline. The change notification is shared by both directions.
func (c *applicationConn) wait(deadline time.Time) {
	if c.changed == nil {
		c.changed = make(chan struct{})
	}
	changed := c.changed
	c.mu.Unlock()
	if deadline.IsZero() {
		<-changed
	} else {
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-changed:
		case <-timer.C:
		}
		timer.Stop()
	}
	c.mu.Lock()
}

func (c *applicationConn) signal() {
	if c.changed != nil {
		close(c.changed)
		c.changed = nil
	}
}

func expired(deadline time.Time) bool {
	return !deadline.IsZero() && !time.Now().Before(deadline)
}

// nextRead lends the consumer one received batch, preserving the separation
// between bytes the application has started reading and unclaimed replies.
func (c *applicationConn) nextRead() error {
	for {
		if expired(c.readDeadline) {
			return os.ErrDeadlineExceeded
		}
		if len(c.readRest) != 0 {
			return nil
		}
		if len(c.received) != 0 {
			c.readRest, c.received = c.received, nil
			c.receiveBytes = 0
			c.signal()
			return nil
		}
		if c.receiveErr != nil {
			return c.receiveErr
		}
		c.wait(c.readDeadline)
	}
}

func (c *applicationConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.nextRead(); err != nil {
		return 0, err
	}
	var n int
	if c.packet {
		c.readRest, n = buf.SplitFirstBytes(c.readRest, p)
	} else {
		c.readRest, n = buf.SplitBytes(c.readRest, p)
	}
	return n, nil
}

func (c *applicationConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.nextRead(); err != nil {
		return nil, err
	}
	mb := c.readRest
	c.readRest = nil
	return mb, nil
}

func (c *applicationConn) Write(p []byte) (int, error) {
	if err := c.write(int64(len(p)), func() buf.MultiBuffer { return buf.MergeBytes(nil, p) }); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *applicationConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if err := c.write(int64(mb.Len()), func() buf.MultiBuffer { return mb }); err != nil {
		buf.ReleaseMulti(mb)
		return err
	}
	return nil
}

func (c *applicationConn) write(size int64, data func() buf.MultiBuffer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return c.receiveErr
	}
	if !c.bound {
		c.attempted += size
	} else if c.uplink != nil {
		c.uplink.Add(size)
	}
	for {
		if c.closed {
			return c.receiveErr
		}
		if c.sendErr != nil {
			return c.sendErr
		}
		if expired(c.writeDeadline) {
			return os.ErrDeadlineExceeded
		}
		// Keep the existing soft policy. A batch may cross the limit, and
		// that then stops later writes until the dispatcher takes the batch.
		if size == 0 || c.limit < 0 || c.sentBytes <= c.limit {
			mb := data()
			if size == 0 {
				buf.ReleaseMulti(mb)
				return nil
			}
			c.sent, _ = buf.MergeMulti(c.sent, mb)
			c.sentBytes += size
			c.accepted = true
			c.signal()
			return nil
		}
		c.wait(c.writeDeadline)
	}
}

func (c *applicationConn) finish(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopInput(io.ErrClosedPipe)
	if c.receiveErr == nil {
		if err == nil {
			err = io.EOF
		}
		c.receiveErr = err
	}
	c.signal()
}

func (c *applicationConn) stopInput(err error) {
	if c.sendErr == nil || c.sendErr == io.EOF {
		c.sendErr = err
		buf.ReleaseMulti(c.sent)
		c.sent, c.sentBytes = nil, 0
	}
}

func (c *applicationConn) abort(err error) {
	c.mu.Lock()
	c.stopInput(err)
	if !c.closed {
		c.closeApplication(err)
	}
	c.signal()
	c.mu.Unlock()
	c.cancel()
}

func (c *applicationConn) closeApplication(err error) {
	c.closed = true
	c.receiveErr = err
	c.readDeadline, c.writeDeadline = time.Time{}, time.Time{}
	buf.ReleaseMulti(c.received)
	buf.ReleaseMulti(c.readRest)
	c.received, c.readRest, c.receiveBytes = nil, nil, 0
}

func (c *applicationConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closeApplication(io.ErrClosedPipe)
	if c.sendErr == nil {
		c.sendErr = io.EOF
	}
	// Once a write was accepted, the route may still own and use its
	// buffers after taking them. EOF lets the outbound finish that work.
	empty := !c.accepted
	c.signal()
	c.mu.Unlock()
	if empty {
		c.cancel()
	}
	return nil
}

func (*applicationConn) LocalAddr() net.Addr  { return &net.TCPAddr{IP: []byte{0, 0, 0, 0}} }
func (*applicationConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: []byte{0, 0, 0, 0}} }

func (c *applicationConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return io.ErrClosedPipe
	}
	c.readDeadline, c.writeDeadline = t, t
	c.signal()
	return nil
}

func (c *applicationConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return io.ErrClosedPipe
	}
	c.readDeadline = t
	c.signal()
	return nil
}

func (c *applicationConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return io.ErrClosedPipe
	}
	c.writeDeadline = t
	c.signal()
	return nil
}

type applicationInput struct{ conn *applicationConn }

func (r applicationInput) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.read(time.Time{})
}

func (r applicationInput) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	return r.read(time.Now().Add(timeout))
}

func (r applicationInput) read(deadline time.Time) (buf.MultiBuffer, error) {
	c := r.conn
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		// The route can observe parent cancellation before the watch runs.
		if err := c.parent.Err(); err != nil {
			c.stopInput(err)
			c.signal()
			return nil, err
		}
		if c.sendErr != nil && c.sendErr != io.EOF {
			return nil, c.sendErr
		}
		if len(c.sent) != 0 {
			mb := c.sent
			for _, counter := range c.nested {
				counter.Add(c.sentBytes)
			}
			c.sent, c.sentBytes = nil, 0
			c.signal()
			return mb, nil
		}
		if c.sendErr != nil {
			return nil, c.sendErr
		}
		if expired(deadline) {
			return nil, buf.ErrReadTimeout
		}
		c.wait(deadline)
	}
}

func (r applicationInput) Interrupt() {
	c := r.conn
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopInput(io.ErrClosedPipe)
	c.signal()
}

func (r applicationInput) SetUplinkCounter(counter stats.Counter) {
	c := r.conn
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bound {
		if counter != nil {
			c.nested = append(c.nested, counter)
		}
		return
	}
	c.bound = true
	c.uplink = counter
	if counter != nil && c.attempted != 0 {
		counter.Add(c.attempted)
	}
	c.attempted = 0
}

type applicationOutput struct{ conn *applicationConn }

func (w applicationOutput) WriteMultiBuffer(mb buf.MultiBuffer) error {
	size := int64(mb.Len())
	if size == 0 {
		buf.ReleaseMulti(mb)
		return nil
	}
	c := w.conn
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.receiveErr == nil && c.limit >= 0 && c.receiveBytes > c.limit {
		c.wait(time.Time{})
	}
	if c.receiveErr != nil {
		buf.ReleaseMulti(mb)
		return io.ErrClosedPipe
	}
	c.received, _ = buf.MergeMulti(c.received, mb)
	c.receiveBytes += size
	c.signal()
	return nil
}

func (w applicationOutput) Close() error {
	c := w.conn
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.receiveErr == nil {
		c.receiveErr = io.EOF
		c.signal()
	}
	return nil
}

func (w applicationOutput) Interrupt() {
	c := w.conn
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || (c.receiveErr == io.EOF && len(c.received) == 0) {
		return
	}
	c.receiveErr = io.ErrClosedPipe
	buf.ReleaseMulti(c.received)
	c.received, c.receiveBytes = nil, 0
	c.signal()
}
