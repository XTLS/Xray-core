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

type carrier struct {
	sync.RWMutex
	tx       sync.Mutex
	sessions map[uint16]*Session
	count    uint16
	active   int
	client   bool
	link     transport.Link
	ready    *sync.Cond
	data     buf.MultiBuffer
	limit    int32
	wake     chan struct{}
	ctx      context.Context
	cancel   context.CancelCauseFunc
	timer    *time.Ticker
}

func newCarrier(parent context.Context, link transport.Link, idle time.Duration, client bool, limit int32) *carrier {
	if _, ok := link.Writer.(*buf.BufferedWriter); !ok {
		gate := buf.NewBufferedWriter(link.Writer)
		gate.SetBuffered(false)
		link.Writer = gate
	}
	ctx, cancel := context.WithCancelCause(parent)
	c := &carrier{sessions: make(map[uint16]*Session, 16), link: link, ctx: ctx, cancel: cancel,
		timer: time.NewTicker(idle), client: client, limit: limit, wake: make(chan struct{}, 1)}
	c.ready = sync.NewCond(&c.tx)
	context.AfterFunc(c.ctx, func() { common.Interrupt(c.link.Reader) })
	go c.sendLoop()
	go c.monitor()
	return c
}

func (c *carrier) admitLocked(s *Session) bool {
	if c.Closed() || s.phase != outputOpen || c.sessions[s.ID] != nil {
		return false
	}
	c.count++
	c.active++
	c.sessions[s.ID] = s
	return true
}

func (c *carrier) wakeSenderTXLocked() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *carrier) fullTXLocked() bool {
	return c.limit >= 0 && c.data.Len() > c.limit
}

// TX owns admission and drain. An entered bounded DATA offer may cross close;
// the next offer observes done. END has already passed the cold phase check.
func (c *carrier) appendEntry(s *Session, frames buf.MultiBuffer, end bool) error {
	c.tx.Lock()
	defer c.tx.Unlock()
	for !c.Closed() && (end || !s.done.Done()) {
		if !c.fullTXLocked() {
			c.data = append(c.data, frames...)
			c.wakeSenderTXLocked()
			return nil
		}
		c.ready.Wait()
	}
	return io.ErrClosedPipe
}

func (c *carrier) unknownEnd(id uint16) {
	// The serial server parser already observed this ID missing and cannot
	// insert another row until admission returns and its KEEP is drained.
	c.tx.Lock()
	defer c.tx.Unlock()
	for !c.Closed() {
		if !c.fullTXLocked() {
			frames := endFrame(id, false)
			c.data = buf.MergeBytes(c.data, frames[0].Bytes())
			buf.ReleaseMulti(frames)
			c.wakeSenderTXLocked()
			return
		}
		c.ready.Wait()
	}
}

// The gate precedes claim/revalidation, and no logical lock spans physical I/O.
func (c *carrier) sendLoop() {
	gate := c.link.Writer.(*buf.BufferedWriter)
	for {
		c.tx.Lock()
		for !c.Closed() && len(c.data) == 0 {
			c.tx.Unlock()
			select {
			case <-c.ctx.Done():
				return
			case <-c.wake:
			}
			c.tx.Lock()
		}
		if c.Closed() {
			c.tx.Unlock()
			return
		}
		c.tx.Unlock()
		gate.Lock()
		if c.writeAndUnlock(c.takePending(), nil) != nil {
			return
		}
	}
}

// The caller owns the writer gate and no logical lock. This prefix cut must
// precede any own raw claim or known-END retirement under that gate.
func (c *carrier) takePending() buf.MultiBuffer {
	c.tx.Lock()
	frames := c.data
	c.data = nil
	c.ready.Broadcast()
	c.tx.Unlock()
	return frames
}

// The caller owns this carrier's locked writer gate and no logical locks.
// Frames transfer here; any unencoded raw remainder must already be released.
func (c *carrier) writeAndUnlock(frames buf.MultiBuffer, err error) error {
	gate := c.link.Writer.(*buf.BufferedWriter)
	if err != nil || c.Closed() {
		buf.ReleaseMulti(frames)
	} else if len(frames) != 0 {
		err = gate.WriteMultiBufferLocked(frames)
	}
	if err != nil {
		c.Lock()
		c.cancel(err)
		c.clearPending()
		c.Unlock()
	}
	gate.Unlock()
	if err != nil {
		c.closeCause(err)
	}
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
	return c.closeCause(nil)
}

func (c *carrier) clearPending() {
	c.tx.Lock()
	buf.ReleaseMulti(c.data)
	c.data = nil
	c.ready.Broadcast()
	c.tx.Unlock()
}

func (c *carrier) closeCause(err error) error {
	c.Lock()
	c.cancel(err) // cancellation precedes the TX drain and every later admission
	c.clearPending()
	c.Unlock()
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
			c.clearPending()
			sessions := c.sessions
			c.sessions, c.active = nil, 0
			c.Unlock()
			for _, s := range sessions {
				s.abort()
			}
			common.Interrupt(c.link.Writer)
			return
		case <-c.timer.C:
			c.Lock()
			idle := c.active == 0 && checkSize == 0 && c.count == checkCount
			if idle {
				c.cancel(nil)
				c.clearPending()
			}
			c.Unlock()
			if idle {
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
	defer func() { c.closeCause(err) }()
	reader := &buf.BufferedReader{Reader: c.link.Reader}
	defer func() { buf.ReleaseMulti(reader.Buffer) }()
	for !c.Closed() {
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
