package outbound

import (
	"context"
	goerrors "errors"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// CreateMuxWorker connects the Mux worker directly to a VLESS transport.
func (h *Handler) CreateMuxWorker(ctx context.Context, dialer internet.Dialer, strategy mux.ClientStrategy) (*mux.ClientWorker, error) {
	ctx, cancel := context.WithCancel(ctx)
	carrier := &muxCarrier{ctx: ctx, cancel: cancel, ready: make(chan struct{})}
	carrier.writeGate = &mux.MutexWriter{Writer: carrier}
	worker, err := mux.NewClientWorker(transport.Link{Reader: carrier, Writer: carrier.writeGate}, strategy)
	if err != nil {
		cancel()
		return nil, err
	}
	// Closing the carrier cannot wait for the monitor to close child links.
	go func() {
		<-worker.WaitClosed()
		cancel()
	}()
	go func() {
		defer worker.Close()
		defer cancel()
		err := h.process(ctx, nil, dialer, carrier)
		cause := errors.Cause(err)
		if err != nil && !goerrors.Is(cause, io.EOF) && !goerrors.Is(cause, io.ErrClosedPipe) && !goerrors.Is(cause, context.Canceled) {
			errors.LogInfoInner(ctx, err, "failed to handle VLESS mux connection")
		}
	}()
	return worker, nil
}

// muxCarrier publishes the VLESS codecs after dialing. Its ready channel
// carries no data. Session writes go directly through the VLESS writer.
type muxCarrier struct {
	ctx       context.Context
	cancel    context.CancelFunc
	ready     chan struct{}
	writeGate *mux.MutexWriter

	activity     *signal.ActivityTimer
	openResponse func() (buf.Reader, error)
	firstWrite   func(buf.MultiBuffer) (buf.Writer, error)
	reader       buf.Reader // used by ClientWorker.fetchOutput
	readErr      error      // deferred until the final batch is consumed
	writer       buf.Writer // accessed under writeGate
}

func (c *muxCarrier) serve(activity *signal.ActivityTimer, response func() (buf.Reader, error), firstWrite func(buf.MultiBuffer) (buf.Writer, error)) error {
	c.activity = activity
	c.openResponse = response
	c.firstWrite = firstWrite
	close(c.ready)

	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-c.ctx.Done():
		return c.ctx.Err()
	case <-timer.C:
		// Match VLESS's first-payload timeout using the same lock as frame writes.
		c.writeGate.Lock()
		var err error
		if c.writer == nil {
			err = c.write(nil)
		}
		c.writeGate.Unlock()
		if err != nil {
			return err
		}
	}
	<-c.ctx.Done()
	return c.ctx.Err()
}

func (c *muxCarrier) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if c.readErr != nil {
		c.cancel()
		return nil, c.readErr
	}
	if c.reader == nil {
		select {
		case <-c.ctx.Done():
			return nil, c.ctx.Err()
		case <-c.ready:
		}
		reader, err := c.openResponse()
		if err != nil {
			c.cancel()
			return nil, err
		}
		c.reader = reader
	}
	mb, err := c.reader.ReadMultiBuffer()
	if !mb.IsEmpty() {
		c.activity.Update()
		c.readErr = err
		return mb, nil
	}
	if err != nil {
		c.cancel()
	}
	return mb, err
}

// WriteMultiBuffer is called under writeGate, which also serializes the codec.
func (c *muxCarrier) WriteMultiBuffer(mb buf.MultiBuffer) error {
	select {
	case <-c.ctx.Done():
		buf.ReleaseMulti(mb)
		return c.ctx.Err()
	case <-c.ready:
		return c.write(mb)
	}
}

func (c *muxCarrier) write(mb buf.MultiBuffer) error {
	if err := c.ctx.Err(); err != nil {
		buf.ReleaseMulti(mb)
		return err
	}
	var err error
	if c.writer == nil {
		c.writer, err = c.firstWrite(mb)
	} else {
		if !mb.IsEmpty() {
			c.activity.Update()
		}
		err = c.writer.WriteMultiBuffer(mb)
	}
	if err != nil {
		c.cancel()
	}
	return err
}

func (c *muxCarrier) Interrupt() {
	c.cancel()
}

// Keep the transport's graceful close when the carrier is ready and idle.
// A write or handshake in progress can need an independent transport abort.
func (c *muxCarrier) stopTransport(conn stat.Connection) {
	if interrupter, ok := stat.TryUnwrapStatsConn(conn).(common.Interruptible); ok {
		select {
		case <-c.ready:
			if c.writeGate.TryLock() {
				c.writeGate.Unlock()
				conn.Close()
				return
			}
		default:
		}
		interrupter.Interrupt()
		return
	}
	conn.Close()
}
