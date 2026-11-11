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
	done           *done.Instance
	timer          *time.Ticker
}

func newCarrier(link transport.Link, idle time.Duration) *carrier {
	c := &carrier{sessionManager: NewSessionManager(), link: link, done: done.New(), timer: time.NewTicker(idle)}
	c.link.Writer = newFrameSender(link.Writer, func() { c.Close() })
	go c.monitor()
	return c
}

func (c *carrier) ActiveConnections() uint32   { return uint32(c.sessionManager.Size()) }
func (c *carrier) Closed() bool                { return c.done.Done() }
func (c *carrier) WaitClosed() <-chan struct{} { return c.done.Wait() }
func (c *carrier) Close() error {
	err := c.done.Close()
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
		NewResponseWriter(meta.SessionID, c.link.Writer, protocol.TransferTypeStream).Close()
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
