package multiplex

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

// Control intents carry no encoded DATA or caller payload.
type carrier struct {
	sync.RWMutex
	sessions             map[uint16]*Session
	readyHead, readyTail *Session
	count                uint16
	active               int
	client               bool
	link                 transport.Link
	control              *sync.Cond
	pendingUnknown       map[uint16]struct{}
	ctx                  context.Context
	cancel               context.CancelCauseFunc
	timer                *time.Ticker
}

func newCarrier(parent context.Context, link transport.Link, idle time.Duration, client bool) *carrier {
	if _, ok := link.Writer.(*PhysicalWriter); !ok {
		link.Writer = &PhysicalWriter{Writer: link.Writer}
	}
	ctx, cancel := context.WithCancelCause(parent)
	c := &carrier{
		sessions: make(map[uint16]*Session, 16), link: link, ctx: ctx, cancel: cancel,
		timer: time.NewTicker(idle), client: client,
	}
	c.control = sync.NewCond(&c.RWMutex)
	c.pendingUnknown = make(map[uint16]struct{})
	context.AfterFunc(c.ctx, func() { common.Interrupt(c.link.Reader) })
	go c.controlLoop()
	go c.monitor()
	return c
}

func (c *carrier) admitLocked(s *Session) bool {
	if c.Closed() || s.phase != outputOpen || c.sessions[s.ID] != nil {
		return false
	}
	c.count++
	c.active++
	c.invalidateUnknownLocked(s.ID)
	c.sessions[s.ID] = s
	return true
}

// These are only cold control/retained-route notifications, never DATA staging.
func (c *carrier) queueReadyLocked(s *Session) {
	if s.listed {
		return
	}
	s.prev, s.next, s.listed = c.readyTail, nil, true
	if c.readyTail != nil {
		c.readyTail.next = s
	} else {
		c.readyHead = s
	}
	c.readyTail = s
	c.control.Broadcast()
}

func (c *carrier) unlinkReadyLocked(s *Session) {
	if !s.listed {
		return
	}
	if s.prev != nil {
		s.prev.next = s.next
	} else {
		c.readyHead = s.next
	}
	if s.next != nil {
		s.next.prev = s.prev
	} else {
		c.readyTail = s.prev
	}
	s.prev, s.next, s.listed = nil, nil, false
}

func (c *carrier) scheduleLocked(s *Session) {
	x := s.flow
	if !c.Closed() && c.sessions[s.ID] == s &&
		(s.phase == outputClosing || x.binding == s &&
			(s.phase == outputOpen && (len(x.response) != 0 || x.responseErr != nil) ||
				s.phase == outputStarting && x.requestErr == nil && len(x.response) != 0)) {
		c.queueReadyLocked(s)
	}
}

func (c *carrier) invalidateUnknownLocked(id uint16) {
	if _, ok := c.pendingUnknown[id]; ok {
		delete(c.pendingUnknown, id)
		c.control.Broadcast()
	}
}

// The parser budgets live intents. Same-ID admission releases withdrawn work;
// there is no queue of obsolete generations that can pin control capacity.
func (c *carrier) unknownEnd(id uint16) {
	c.Lock()
	defer c.Unlock()
	for !c.Closed() {
		if _, duplicate := c.pendingUnknown[id]; duplicate {
			return
		}
		if len(c.pendingUnknown) < 16 {
			c.pendingUnknown[id] = struct{}{}
			c.control.Broadcast()
			return
		}
		c.control.Wait()
	}
}

func (c *carrier) controlLoop() {
	gate := c.link.Writer.(*PhysicalWriter)
	for {
		c.Lock()
		for !c.Closed() && c.readyHead == nil && len(c.pendingUnknown) == 0 {
			c.control.Wait()
		}
		selected, closed := c.readyHead, c.Closed()
		c.Unlock()
		if closed {
			return
		}
		gate.Lock()
		var frames buf.MultiBuffer
		var err error
		c.Lock()
		if !c.Closed() {
			for id := range c.pendingUnknown {
				c.invalidateUnknownLocked(id)
				frames = endFrame(id, false)
				break
			}
		}
		c.Unlock()
		// Give both live controls and retained output one bounded service turn.
		if selected != nil {
			raw, terminal := c.responseTurn(selected)
			if terminal {
				frames = append(frames, endFrame(selected.ID, selected.endFailed)...)
			} else if len(raw) != 0 {
				var own buf.MultiBuffer
				own, err = selected.encodeBatch(&raw)
				frames = append(frames, own...)
				buf.ReleaseMulti(raw)
			}
		}
		if c.writeAndUnlock(frames, err) != nil {
			return
		}
	}
}

// No logical lock spans physical I/O or a codec/address callback.
func (c *carrier) writeAndUnlock(frames buf.MultiBuffer, err error) error {
	gate := c.link.Writer.(*PhysicalWriter)
	if err != nil || c.Closed() {
		buf.ReleaseMulti(frames)
	} else if len(frames) != 0 {
		err = gate.Writer.WriteMultiBuffer(frames)
	}
	if err != nil {
		c.cancel(err)
	}
	gate.Unlock()
	return err
}

func (c *carrier) ActiveConnections() uint32 {
	c.RLock()
	defer c.RUnlock()
	return uint32(c.active)
}
func (c *carrier) Closed() bool                { return c.ctx.Err() != nil }
func (c *carrier) WaitClosed() <-chan struct{} { return c.ctx.Done() }
func (c *carrier) Context() context.Context    { return c.ctx }

// Err reports the first close cause, excluding normal cancellation.
func (c *carrier) Err() error {
	err := context.Cause(c.ctx)
	if err == context.Canceled {
		return nil
	}
	return err
}

func (c *carrier) Close() error {
	c.cancel(nil)
	return nil
}

func (c *carrier) monitor() {
	defer c.timer.Stop()
	for {
		c.RLock()
		checkSize, checkCount := c.active, c.count
		c.RUnlock()
		select {
		case <-c.ctx.Done():
			c.Lock()
			for c.readyHead != nil {
				c.unlinkReadyLocked(c.readyHead)
			}
			c.pendingUnknown = nil
			c.control.Broadcast()
			sessions := c.sessions
			c.sessions, c.active = nil, 0
			c.Unlock()
			for id, s := range sessions {
				if !s.seal(false, false) {
					delete(sessions, id)
				}
			}
			for _, s := range sessions {
				s.cleanup()
			}
			common.Interrupt(c.link.Writer)
			return
		case <-c.timer.C:
			c.Lock()
			idle := c.active == 0 && checkSize == 0 && c.count == checkCount
			if idle {
				c.cancel(nil)
			}
			c.Unlock()
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
	c.RLock()
	s, found := c.sessions[meta.SessionID]
	if found && s.phase != outputOpen {
		s = nil
	}
	c.RUnlock()
	if !found && !c.client {
		c.unknownEnd(meta.SessionID)
	}
	return copyFramePayload(reader, s, meta.Target)
}

func (c *carrier) handleStatusEnd(meta *FrameMetadata, reader *buf.BufferedReader) error {
	c.RLock()
	s := c.sessions[meta.SessionID]
	c.RUnlock()
	if s != nil {
		s.abort()
	}
	return discardFrame(meta, reader)
}

func (c *carrier) run(ctx context.Context, accept func(context.Context, *FrameMetadata, *buf.BufferedReader) error) {
	var err error
	defer func() { c.cancel(err) }()
	reader := &buf.BufferedReader{Reader: c.link.Reader}
	defer func() { buf.ReleaseMulti(reader.Buffer) }()
	for !c.Closed() {
		var meta FrameMetadata
		err = meta.Unmarshal(reader, session.IsReverseMuxFromContext(ctx))
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
					err = accept(session.ContextWithIsReverseMux(ctx, false), &meta, reader)
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
