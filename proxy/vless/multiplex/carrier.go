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
	"github.com/xtls/xray-core/transport"
)

// carrier owns the physical frame loop and child registry for either multiplex role.
// Client and server roles differ only in initiating or accepting new children.
type carrier struct {
	sessionManager *SessionManager
	link           transport.Link
	pending        chan buf.MultiBuffer // client-only encoded write lead
	ctx            context.Context
	cancel         context.CancelCauseFunc
	timer          *time.Ticker
}

func newCarrier(link transport.Link, idle time.Duration, queueWrites bool) *carrier {
	// Reuse the prepared codec gate so physical cancellation sees its lock.
	if _, ok := link.Writer.(*buf.BufferedWriter); !ok {
		writer := buf.NewBufferedWriter(link.Writer)
		writer.SetBuffered(false)
		link.Writer = writer
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	c := &carrier{sessionManager: NewSessionManager(), link: link, ctx: ctx, cancel: cancel, timer: time.NewTicker(idle)}
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
		case <-c.ctx.Done():
			buf.ReleaseMulti(mb)
			return io.ErrClosedPipe
		}
	}
	err := c.link.Writer.WriteMultiBuffer(mb)
	if err != nil {
		c.closeCause(err)
	}
	return err
}

// sendLoop is the sole client physical writer; server writes remain direct.
func (c *carrier) sendLoop() {
	var err error
	defer func() { c.closeCause(err) }()
	for {
		select {
		case <-c.ctx.Done():
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
			if err = c.link.Writer.WriteMultiBuffer(data); err != nil {
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
func (c *carrier) Closed() bool                { return c.ctx.Err() != nil }
func (c *carrier) WaitClosed() <-chan struct{} { return c.ctx.Done() }

// Err reports the first close cause, excluding normal cancellation.
func (c *carrier) Err() error {
	err := context.Cause(c.ctx)
	if err == context.Canceled {
		return nil
	}
	return err
}

func (c *carrier) Close() error {
	return c.closeCause(nil)
}

func (c *carrier) closeCause(err error) error {
	c.cancel(err)
	c.discardPending()
	common.Interrupt(c.link.Reader)
	return nil
}

func (c *carrier) monitor() {
	defer c.timer.Stop()
	for {
		c.sessionManager.RLock()
		checkSize, checkCount := c.sessionManager.active, int(c.sessionManager.count)
		c.sessionManager.RUnlock()
		select {
		case <-c.ctx.Done():
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
	var err error
	defer func() { c.closeCause(err) }()
	reader := &buf.BufferedReader{Reader: c.link.Reader}
	for ctx.Err() == nil {
		var meta FrameMetadata
		err = meta.Unmarshal(reader, session.IsReverseMultiplexFromContext(ctx))
		if errors.Cause(err) == io.EOF {
			err = nil // clean EOF before the next metadata prefix
			return
		}
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
					err = accept(session.ContextWithIsReverseMultiplex(ctx, false), &meta, reader)
				}
			default:
				err = errors.New("unknown status: ", meta.SessionStatus)
			}
		}
		if err != nil {
			errors.LogInfoInner(ctx, err, "failed to process multiplex frame")
			return
		}
	}
}
