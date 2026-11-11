package multiplex

import (
	"context"
	"io"
	"sync/atomic"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

// Connection owns the encoded stream and its bounded receive queue.
type Connection struct {
	ctx      context.Context
	cancel   context.CancelFunc
	conn     stat.Connection
	stop     func() bool
	gate     *buf.BufferedWriter
	ready    atomic.Bool
	reader   *pipe.Reader
	writer   buf.Writer
	activity *signal.ActivityTimer
	readErr  error
}

func NewConnection(ctx context.Context, cancel context.CancelFunc, conn stat.Connection) *Connection {
	c := &Connection{ctx: ctx, cancel: cancel, conn: conn}
	c.stop = context.AfterFunc(ctx, c.closeTransport)
	return c
}

func (c *Connection) Close() {
	c.cancel()
	c.stop()
	c.closeTransport()
}

// A quiescent writer can drain and send EOF. Handshake or blocked writes
// need interruption before transport Close attempts to acquire their locks.
func (c *Connection) closeTransport() {
	if c.ready.Load() && c.gate.TryLock() {
		c.gate.Unlock()
		c.conn.Close()
		return
	}
	common.Interrupt(stat.TryUnwrapStatsConn(c.conn))
}

func (c *Connection) WrapWriter(writer buf.Writer, activity *signal.ActivityTimer) buf.Writer {
	c.writer, c.activity = writer, activity
	return c
}

func (c *Connection) ReadMultiBuffer() (buf.MultiBuffer, error) {
	data, err := c.reader.ReadMultiBuffer()
	// The producer publishes readErr before closing the pipe writer.
	if err == io.EOF && c.readErr != nil {
		err = c.readErr
	}
	return data, err
}

func (c *Connection) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if err := c.ctx.Err(); err != nil {
		buf.ReleaseMulti(mb)
		return err
	}
	if !mb.IsEmpty() {
		c.activity.Update()
	}
	err := c.writer.WriteMultiBuffer(mb)
	if err != nil {
		c.cancel()
	}
	return err
}

func (c *Connection) Interrupt() {
	c.cancel()
	c.reader.Interrupt()
}

func (c *Connection) Run(writer buf.Writer, activity *signal.ActivityTimer, receiveLimit int32, openResponse func() (buf.Reader, error), start func(context.Context, *transport.Link) error) error {
	var ok bool
	c.gate, ok = writer.(*buf.BufferedWriter)
	if !ok {
		c.gate = buf.NewBufferedWriter(c.WrapWriter(writer, activity))
		c.gate.SetBuffered(false)
	}
	c.ready.Store(true)
	reader, receiver := pipe.New(pipe.WithSizeLimit(receiveLimit))
	c.reader = reader
	defer reader.Interrupt()
	go func() {
		response, err := openResponse()
		if err == nil {
			err = buf.Copy(response, receiver, buf.UpdateActivity(activity))
		}
		c.readErr = err
		receiver.Close()
	}()
	return start(c.ctx, &transport.Link{Reader: c, Writer: c.gate})
}
