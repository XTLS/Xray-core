package multiplex

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
)

// inboundFlow owns native route input and persistent binding state. Its response
// mailbox retains native bytes until the current binding emitter claims them.
// Locks nest association map -> flow -> one carrier; I/O is outside them.
type inboundFlow struct {
	access                  sync.Mutex
	requestWake             *sync.Cond
	responseWake            *sync.Cond
	request, response       buf.MultiBuffer
	requestErr, responseErr error
	uplinkCounter           stats.Counter
	uplinkPending           int64
	uplinkBound             bool
	limit                   int32
	binding                 *Session
	GlobalID                [8]byte
	Expire                  time.Time
}

func newInboundFlow(ctx context.Context, id [8]byte) *inboundFlow {
	x := &inboundFlow{limit: policy.BufferPolicyFromContext(ctx).PerConnection, GlobalID: id}
	x.requestWake = sync.NewCond(&x.access)
	x.responseWake = sync.NewCond(&x.access)
	return x
}

func (x *inboundFlow) notify() {
	x.requestWake.Broadcast()
	x.responseWake.Broadcast()
}

// SetUplinkCounter binds attempted-input accounting once, including disabled stats.
func (x *inboundFlow) SetUplinkCounter(counter stats.Counter) {
	x.access.Lock()
	if x.uplinkBound {
		x.access.Unlock()
		return
	}
	x.uplinkCounter, x.uplinkBound = counter, true
	pending := x.uplinkPending
	x.uplinkPending = 0
	x.access.Unlock()
	if counter != nil && pending != 0 {
		counter.Add(pending)
	}
}

func (x *inboundFlow) ReadMultiBuffer() (buf.MultiBuffer, error) {
	x.access.Lock()
	defer x.access.Unlock()
	return x.readLocked(nil)
}

func (x *inboundFlow) ReadMultiBufferTimeout(duration time.Duration) (buf.MultiBuffer, error) {
	x.access.Lock()
	defer x.access.Unlock()
	if len(x.request) > 0 || x.requestErr != nil {
		return x.readLocked(nil)
	}
	timedOut := false
	timer := time.AfterFunc(duration, func() {
		x.access.Lock()
		timedOut = true
		x.requestWake.Broadcast()
		x.access.Unlock()
	})
	defer timer.Stop()
	return x.readLocked(&timedOut)
}

// readLocked has no timeout closure or escaping flag on ordinary native reads.
func (x *inboundFlow) readLocked(timedOut *bool) (buf.MultiBuffer, error) {
	for len(x.request) == 0 && x.requestErr == nil && (timedOut == nil || !*timedOut) {
		x.requestWake.Wait()
	}
	if len(x.request) > 0 {
		data := x.request
		x.request = nil
		x.requestWake.Broadcast()
		return data, nil
	}
	if x.requestErr != nil {
		return nil, x.requestErr
	}
	return nil, buf.ErrReadTimeout
}

// accept leaves rejected data with the parser so a failed retained route can
// restart with the very same first packet and destination.
func (x *inboundFlow) accept(data buf.MultiBuffer, binding *Session) error {
	x.access.Lock()
	if !x.uplinkBound {
		x.uplinkPending += int64(data.Len())
	} else if counter := x.uplinkCounter; counter != nil {
		x.access.Unlock()
		counter.Add(int64(data.Len()))
		x.access.Lock()
	}
	defer x.access.Unlock()
	for {
		if x.requestErr != nil || x.binding != binding || binding.parent.Closed() {
			return io.ErrClosedPipe
		}
		if x.limit < 0 || x.request.Len() <= x.limit {
			if len(x.request) == 0 {
				x.request = data
			} else {
				x.request, _ = buf.MergeMulti(x.request, data)
			}
			x.requestWake.Broadcast()
			return nil
		}
		x.requestWake.Wait()
	}
}

// Interrupt is native request abort. Ordinary wire EOF instead seals this
// input in Session.close, preserving payload already accepted from the parser.
func (x *inboundFlow) Interrupt() {
	x.access.Lock()
	x.requestErr = io.ErrClosedPipe
	x.request = buf.ReleaseMulti(x.request)
	x.requestWake.Broadcast()
	x.access.Unlock()
}

type flowOutput struct{ *inboundFlow }

func (w *flowOutput) Interrupt()   { w.finish(true) }
func (w *flowOutput) Close() error { w.finish(false); return nil }
func (x *inboundFlow) finish(abort bool) {
	x.access.Lock()
	if x.responseErr == nil {
		x.responseErr = io.EOF
	}
	if abort && x.responseErr != io.ErrClosedPipe {
		x.responseErr = io.ErrClosedPipe
	}
	if abort {
		x.response = buf.ReleaseMulti(x.response)
	}
	if s := x.binding; abort && s != nil {
		c := s.parent
		c.Lock()
		if s.flow == x && s.phase == outputOpen {
			s.closeLocked(x, true, true)
		}
		c.Unlock()
	}
	x.notify()
	x.access.Unlock()
}

func (x *inboundFlow) expire() {
	x.access.Lock()
	if x.requestErr == nil {
		x.requestErr = io.EOF
	}
	x.access.Unlock()
	x.finish(true)
}

// WriteMultiBuffer admits the whole raw offer under the original soft policy.
// Response-capacity waiters are separate from request readers.
func (w *flowOutput) WriteMultiBuffer(data buf.MultiBuffer) error {
	x := w.inboundFlow
	x.access.Lock()
	defer x.access.Unlock()
	for x.responseErr == nil && x.limit >= 0 && x.response.Len() > x.limit {
		x.responseWake.Wait()
	}
	if x.responseErr != nil {
		buf.ReleaseMulti(data)
		return io.ErrClosedPipe
	}
	if data.IsEmpty() {
		buf.ReleaseMulti(data)
		return nil
	}
	if len(x.response) == 0 {
		x.response = data
	} else {
		x.response, _ = buf.MergeMulti(x.response, data)
	}
	x.responseWake.Broadcast()

	return nil
}

// Each binding writes directly after the physical gate. The ordered control
// prefix is detached before this owner's raw claim, never at completion.
func (w *ServerWorker) emitResponse(s *Session, x *inboundFlow) {
	c := s.parent
	gate := c.link.Writer.(*buf.BufferedWriter)
	for {
		x.access.Lock()
		for {
			if c.Closed() {
				x.access.Unlock()
				return
			}
			if x.binding != s {
				x.access.Unlock()
				w.emitResponseEnd(s, x)
				return
			}
			if s.phase == outputStarting && x.requestErr != nil {
				x.responseWake.Wait()
				continue
			}
			if len(x.response) != 0 {
				break
			}
			if x.responseErr != nil && s.phase == outputOpen {
				c.Lock()
				s.closeLocked(x, x.responseErr == io.ErrClosedPipe, true)
				c.Unlock()
				x.access.Unlock()
				w.emitResponseEnd(s, x)
				return
			}
			x.responseWake.Wait()
		}
		x.access.Unlock()

		gate.Lock()
		frames := c.takePending()
		x.access.Lock()
		var data buf.MultiBuffer
		if !c.Closed() && x.binding == s &&
			(s.phase == outputOpen || s.phase == outputStarting) &&
			(s.phase != outputStarting || x.requestErr == nil) && len(x.response) != 0 {
			if s.transferType == protocol.TransferTypeStream {
				for n := 0; n < 4 && !x.response.IsEmpty(); n++ {
					var chunk buf.MultiBuffer
					x.response, chunk = buf.SplitSize(x.response, 8*1024)
					data = append(data, chunk...)
				}
			} else {
				n := min(4, len(x.response))
				data, x.response = x.response[:n:n], x.response[n:]
			}
			if len(x.response) == 0 || s.transferType == protocol.TransferTypeStream && x.response.IsEmpty() {
				x.response = buf.ReleaseMulti(x.response)
				x.response = nil
			}
			x.responseWake.Broadcast()
		}
		x.access.Unlock()
		var err error
		if len(data) != 0 {
			var own buf.MultiBuffer
			own, err = s.encodeBatch(&data)
			buf.ReleaseMulti(data)
			frames = append(frames, own...)
		}
		if c.writeAndUnlock(frames, err) != nil {
			return
		}
	}
}

// Gate -> prefix cut -> exact known-END retirement preserves every older
// control before replacement output; stale own END still flushes its prefix.
func (w *ServerWorker) emitResponseEnd(s *Session, x *inboundFlow) {
	c := s.parent
	gate := c.link.Writer.(*buf.BufferedWriter)
	gate.Lock()
	frames := c.takePending()
	c.Lock()
	live := !c.Closed() && s.flow == x && s.phase == outputClosing && c.sessions[s.ID] == s
	failed := s.endFailed
	if live {
		delete(c.sessions, s.ID)
	}
	c.Unlock()
	if live {
		frames = append(frames, endFrame(s.ID, failed)...)
	}
	c.writeAndUnlock(frames, nil)
}

func (w *ServerWorker) bindXUDP(ctx context.Context, meta *FrameMetadata, reader *buf.BufferedReader) error {
	data, err := readPacket(reader, meta.Target)
	if err != nil {
		return err
	}
	ctx = session.ContextWithTimeoutOnly(ctx, true)
	XUDPManager.Lock()
	x := XUDPManager.Map[meta.GlobalID]
	fresh := x == nil
	if fresh {
		x = newInboundFlow(ctx, meta.GlobalID)
		XUDPManager.Map[meta.GlobalID] = x
	}
	x.access.Lock()
	previous := x.binding
	if previous != nil {
		previous.parent.RLock()
		starting := previous.phase == outputStarting
		previous.parent.RUnlock()
		if starting {
			x.access.Unlock()
			XUDPManager.Unlock()
			buf.ReleaseMulti(data)
			errors.LogWarningInner(ctx, errors.New("conflict"), "XUDP hit ", meta.GlobalID)
			return nil
		}
	}
	s := &Session{
		parent: w.carrier, ID: meta.SessionID, phase: outputStarting,
		transferType: protocol.TransferTypePacket, flow: x,
	}
	if previous != nil {
		previous.parent.Lock()
		previous.closeLocked(x, true, true)
		previous.parent.Unlock()
	}
	w.Lock()
	if w.Closed() || w.sessions[s.ID] != nil {
		w.Unlock()
		x.access.Unlock()
		if fresh {
			delete(XUDPManager.Map, meta.GlobalID)
		}
		XUDPManager.Unlock()
		buf.ReleaseMulti(data)
		return errors.New("failed to add new session")
	}
	w.sessions[s.ID] = s // custody precedes first-packet admission, not activity
	x.binding, x.Expire = s, time.Time{}
	x.notify()
	w.Unlock()
	x.access.Unlock()
	XUDPManager.Unlock()
	go w.emitResponse(s, x)
	dest := meta.Target
	for {
		if fresh {
			go w.dispatchFlow(ctx, dest, x)
		}
		err = x.accept(data, s)
		if err == nil || fresh {
			break
		}

		replacement := newInboundFlow(ctx, meta.GlobalID)
		replacement.binding = s
		XUDPManager.Lock()
		x.access.Lock()
		w.Lock()
		live := !w.Closed() && s.phase == outputStarting && s.flow == x &&
			w.sessions[s.ID] == s && x.binding == s
		if !live {
			if s.flow == x {
				s.closeLocked(x, false, false)
			}
			w.Unlock()
			x.access.Unlock()
			XUDPManager.Unlock()
			buf.ReleaseMulti(data)
			s.abort()
			return nil
		}
		x.binding, x.Expire = nil, time.Now().Add(time.Minute)
		x.notify()
		current := XUDPManager.Map[meta.GlobalID]
		replaced := current == x || current == nil
		if replaced {
			x.responseErr = io.ErrClosedPipe
			XUDPManager.Map[meta.GlobalID] = replacement
			s.flow = replacement // same Starting identity, same offered packet
		}
		w.Unlock()
		x.access.Unlock()
		XUDPManager.Unlock()
		x.expire()
		if !replaced {
			break
		}
		go w.emitResponse(s, replacement)
		x, fresh = replacement, true
	}
	if err != nil {
		buf.ReleaseMulti(data)
	}
	XUDPManager.Lock()
	x.access.Lock()
	w.Lock()
	admitted := !w.Closed() && XUDPManager.Map[meta.GlobalID] == x && x.binding == s &&
		w.sessions[s.ID] == s && s.flow == x && s.phase == outputStarting
	if admitted {
		w.count++
		if x.responseErr == nil || len(x.response) != 0 {
			s.phase = outputOpen
			w.active++
		} else {
			s.closeLocked(x, x.responseErr == io.ErrClosedPipe, true)
		}
		x.notify()
	}
	w.Unlock()
	x.access.Unlock()
	XUDPManager.Unlock()
	if !admitted {
		s.abort()
		return errors.New("failed to add new session")
	}
	return nil
}
