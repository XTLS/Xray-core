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
	sessions map[uint16]*Session

	ready      map[uint16]*Session // nil is a bounded END for an unknown wire ID
	unknown    int
	count      uint16
	active     int
	client     bool
	link       transport.Link
	writeMutex sync.Mutex
	control    *sync.Cond
	ctx        context.Context
	cancel     context.CancelCauseFunc
	timer      *time.Timer
}

func newCarrier(parent context.Context, link transport.Link, idle time.Duration, client bool) *carrier {
	ctx, cancel := context.WithCancelCause(parent)
	c := &carrier{
		sessions: make(map[uint16]*Session, 16), link: link, ctx: ctx, cancel: cancel,
		client: client,
	}
	c.control = sync.NewCond(&c.RWMutex)
	c.ready = make(map[uint16]*Session)
	context.AfterFunc(c.ctx, func() { common.Interrupt(c.link.Reader) })
	c.Lock()
	checkSize, checkCount := c.active, c.count
	c.timer = time.AfterFunc(idle, func() {
		c.Lock()
		defer c.Unlock()
		if c.Closed() {
			return
		}
		if c.active == 0 && checkSize == 0 && c.count == checkCount {
			c.cancel(nil)
			return
		}
		checkSize, checkCount = c.active, c.count
		c.timer.Reset(idle)
	})
	c.Unlock()
	context.AfterFunc(c.ctx, c.shutdown)
	go c.controlLoop()
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

func (c *carrier) queueReadyLocked(s *Session) {
	if c.ready[s.ID] != s {
		c.ready[s.ID] = s
		c.control.Broadcast()
	}
}

func (c *carrier) scheduleLocked(s *Session) {
	if !c.Closed() && c.sessions[s.ID] == s && (s.phase == outputDone || s.packetReady()) {
		c.queueReadyLocked(s)
	}
}

func (c *carrier) invalidateUnknownLocked(id uint16) bool {
	if s, ok := c.ready[id]; ok && s == nil {
		delete(c.ready, id)
		c.unknown--
		c.control.Broadcast()
		return true
	}
	return false
}

func (c *carrier) unknownEnd(id uint16) {
	c.Lock()
	defer c.Unlock()
	for !c.Closed() {
		if _, queued := c.ready[id]; queued || c.sessions[id] != nil {
			return
		}
		if c.unknown < 16 {
			c.ready[id] = nil
			c.unknown++
			c.control.Broadcast()
			return
		}
		c.control.Wait()
	}
}

func (c *carrier) controlLoop() {
	c.Lock()
	defer c.Unlock()
	for !c.Closed() {
		if len(c.ready) == 0 {
			c.control.Wait()
			continue
		}
		// Advance the iterator under the lock. Physical sends never hold it.
		for id, selected := range c.ready {
			c.Unlock()
			c.writeMutex.Lock()
			var frames buf.MultiBuffer
			var err error
			raw, terminal := c.responseTurn(id, selected)
			if terminal {
				frames = endFrame(id, selected != nil && selected.endFailed)
			} else if len(raw) != 0 {
				frames, err = selected.encodeBatch(&raw)
				buf.ReleaseMulti(raw)
			}
			err = c.writeAndUnlock(frames, err)
			c.Lock()
			if err != nil || c.Closed() {
				return
			}
		}
	}
}

// No logical lock spans physical I/O or a codec/address callback.
func (c *carrier) writeAndUnlock(frames buf.MultiBuffer, err error) error {
	if err != nil || c.Closed() {
		buf.ReleaseMulti(frames)
	} else if len(frames) != 0 {
		if r, ok := c.link.Reader.(*responseReader); ok {
			r.activity.Update()
		}
		err = c.link.Writer.WriteMultiBuffer(frames)
	}
	if err != nil {
		c.cancel(err)
	}
	c.writeMutex.Unlock()
	return err
}

func (c *carrier) ActiveConnections() uint32 {
	c.RLock()
	defer c.RUnlock()
	return uint32(c.active)
}
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
	c.cancel(nil)
	return nil
}

func (c *carrier) shutdown() {
	c.Lock()
	c.timer.Stop()
	c.ready = nil
	c.control.Broadcast()
	sessions := c.sessions
	c.sessions, c.active = nil, 0
	c.Unlock()
	for _, s := range sessions {
		s.abort()
	}
	common.Interrupt(c.link.Writer)
}

func (c *carrier) readFrame(ctx context.Context, meta *FrameMetadata, reader *buf.BufferedReader, accept func(context.Context, *FrameMetadata, *buf.BufferedReader) error) error {
	var target *Session
	data := meta.Option.Has(OptionData)
	switch meta.SessionStatus {
	case SessionStatusNew:
		if accept != nil {
			return accept(session.ContextWithIsReverseMux(ctx, false), meta, reader)
		}
	case SessionStatusKeep:
		if !data {
			return nil
		}
		c.RLock()
		s, found := c.sessions[meta.SessionID]
		if found && s.phase == outputOpen {
			target = s
		}
		c.RUnlock()
		if !found && !c.client {
			c.unknownEnd(meta.SessionID)
		}
	case SessionStatusEnd:
		c.RLock()
		s := c.sessions[meta.SessionID]
		c.RUnlock()
		if s != nil {
			s.abort()
		}
	case SessionStatusKeepAlive:
	default:
		return errors.New("unknown status: ", meta.SessionStatus)
	}
	if data {
		return copyFramePayload(reader, target, meta.Target)
	}
	return nil
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
			err = frameReadError(c.readFrame(ctx, &meta, reader, accept))
		}
		if err != nil {
			errors.LogInfoInner(ctx, err, "failed to process multiplex frame")
			return
		}
	}
}
