package multiplex

import (
	"context"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport"
)

// carrier owns the physical frame loop and child registry for either mux role.
// Client and server roles differ only in initiating or accepting new children.
type carrier struct {
	sessionManager *SessionManager
	link           transport.Link
	pending        chan buf.MultiBuffer // client-only encoded write lead
	done           *done.Instance
	timer          *time.Ticker
}

func newCarrier(link transport.Link, idle time.Duration, queueWrites bool) *carrier {
	// Reuse the prepared codec gate so physical cancellation sees its lock.
	if _, ok := link.Writer.(*buf.BufferedWriter); !ok {
		writer := buf.NewBufferedWriter(link.Writer)
		writer.SetBuffered(false)
		link.Writer = writer
	}
	c := &carrier{sessionManager: NewSessionManager(), link: link, done: done.New(), timer: time.NewTicker(idle)}
	if queueWrites {
		c.pending = make(chan buf.MultiBuffer, 2)
		go c.sendLoop()
	}
	go c.monitor()
	return c
}

// WriteMultiBuffer takes native write custody and closes the carrier on failure.
func (c *carrier) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if c.Closed() {
		buf.ReleaseMulti(mb)
		return io.ErrClosedPipe
	}
	if c.pending != nil {
		select {
		case c.pending <- mb:
			if c.Closed() {
				c.discardPending()
			}
			return nil // the client carrier now owns accepted encoded bytes
		case <-c.done.Wait():
			buf.ReleaseMulti(mb)
			return io.ErrClosedPipe
		}
	}
	err := c.link.Writer.WriteMultiBuffer(mb)
	if err != nil {
		c.Close()
	}
	return err
}

// sendLoop is the sole client physical writer; server writes remain direct.
func (c *carrier) sendLoop() {
	defer c.Close()
	for {
		select {
		case <-c.done.Wait():
			return
		case data := <-c.pending:
			select {
			case next := <-c.pending:
				data, _ = buf.MergeMulti(data, next)
			default:
			}
			if c.Closed() {
				buf.ReleaseMulti(data)
				return
			}
			if err := c.link.Writer.WriteMultiBuffer(data); err != nil {
				return
			}
		}
	}
}

// Drain only accepted queue ownership, before arbitrary foreign interruption.
func (c *carrier) discardPending() {
	for {
		select {
		case data := <-c.pending:
			buf.ReleaseMulti(data)
		default:
			return
		}
	}
}

func (c *carrier) ActiveConnections() uint32   { return uint32(c.sessionManager.Size()) }
func (c *carrier) Closed() bool                { return c.done.Done() }
func (c *carrier) WaitClosed() <-chan struct{} { return c.done.Wait() }
func (c *carrier) Close() error {
	err := c.done.Close()
	c.discardPending()
	common.Interrupt(c.link.Reader)
	return err
}

func (c *carrier) monitor() {
	defer c.timer.Stop()
	for {
		checkSize, checkCount := c.sessionManager.Size(), c.sessionManager.Count()
		select {
		case <-c.done.Wait():
			c.sessionManager.Close()
			common.Interrupt(c.link.Writer)
			return
		case <-c.timer.C:
			if c.sessionManager.CloseIfNoSessionAndIdle(checkSize, checkCount) {
				common.Must(c.Close())
			}
		}
	}
}

func discardFrame(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if meta.Option.Has(OptionData) {
		return copyFramePayload(reader, nil, meta.Target)
	}
	return nil
}

func (c *carrier) handleStatusKeep(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if !meta.Option.Has(OptionData) {
		return nil
	}
	s, found := c.sessionManager.Get(meta.SessionID)
	if !found {
		NewResponseWriter(meta.SessionID, c, protocol.TransferTypeStream).Close()
	} else {
		s.parent.RLock()
		closed := s.closed
		s.parent.RUnlock()
		if closed {
			s = nil
		} // drain without a second END or a retained XUDP write
	}
	return copyFramePayload(reader, s, meta.Target)
}

func (c *carrier) handleStatusEnd(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if s, found := c.sessionManager.Get(meta.SessionID); found {
		s.Close()
	}
	return discardFrame(meta, reader)
}

func (c *carrier) run(ctx context.Context, accept func(context.Context, *FrameMetadata, *buf.BufferedReader) error) {
	defer c.Close()
	reader := &buf.BufferedReader{Reader: c.link.Reader}
	for ctx.Err() == nil {
		var meta FrameMetadata
		err := meta.Unmarshal(reader, session.IsReverseMuxFromContext(ctx))
		if err == nil {
			switch meta.SessionStatus {
			case SessionStatusKeepAlive:
				err = discardFrame(&meta, reader)
			case SessionStatusKeep:
				err = c.handleStatusKeep(&meta, reader)
			case SessionStatusEnd:
				err = c.handleStatusEnd(&meta, reader)
			case SessionStatusNew:
				if accept == nil {
					err = discardFrame(&meta, reader)
				} else {
					err = accept(session.ContextWithIsReverseMux(ctx, false), &meta, reader)
				}
			default:
				err = errors.New("unknown status: ", meta.SessionStatus)
			}
		}
		if err != nil {
			if errors.Cause(err) != io.EOF {
				errors.LogInfoInner(ctx, err, "failed to process mux frame")
			}
			return
		}
	}
}
