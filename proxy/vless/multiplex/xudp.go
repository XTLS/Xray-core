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
// packet response mailbox retains native bytes until the physical sender claims them.
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
	if s := x.binding; s != nil {
		c := s.parent
		c.Lock()
		if abort && s.phase == outputOpen {
			s.closeLocked(x, true, true)
		}
		c.scheduleLocked(s)
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
	if s := x.binding; s != nil {
		s.parent.Lock()
		s.parent.scheduleLocked(s)
		s.parent.Unlock()
	}
	return nil
}

// One gated actor claims packet data or retires one exact terminal identity.
// It returns custody only; the sender encodes after both logical locks release.
func (c *carrier) responseTurn(s *Session) (buf.MultiBuffer, bool) {
	x := s.flow // immutable after publication
	if x != nil {
		x.access.Lock()
		defer x.access.Unlock()
	}
	c.Lock()
	defer c.Unlock()
	c.unlinkReadyLocked(s)
	if c.Closed() || c.sessions[s.ID] != s {
		return nil, false
	}
	if x != nil && s.phase == outputOpen && x.binding == s && len(x.response) == 0 && x.responseErr != nil {
		s.closeLocked(x, x.responseErr == io.ErrClosedPipe, true)
	}
	if s.phase == outputClosing {
		c.unlinkReadyLocked(s)
		delete(c.sessions, s.ID)
		return nil, true
	}
	if x == nil || x.binding != s || (s.phase != outputOpen && s.phase != outputStarting) ||
		s.phase == outputStarting && x.requestErr != nil || len(x.response) == 0 {
		return nil, false
	}
	n := min(4, len(x.response))
	data := x.response[:n:n]
	x.response = x.response[n:]
	if len(x.response) == 0 {
		x.response = buf.ReleaseMulti(x.response)
		x.response = nil
	}
	x.responseWake.Broadcast()
	// A terminal follow-up cannot run until this DATA turn completes physically.
	c.scheduleLocked(s)
	return data, false
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
	w.invalidateUnknownLocked(s.ID)
	w.sessions[s.ID] = s // custody precedes first-packet admission, not activity
	x.binding, x.Expire = s, time.Time{}
	x.notify()
	w.scheduleLocked(s)
	w.Unlock()
	x.access.Unlock()
	XUDPManager.Unlock()
	dest := meta.Target
	for {
		if fresh {
			go w.dispatchFlow(ctx, dest, x, &flowOutput{x})
		}
		err = x.accept(data, s)
		if err == nil || fresh {
			break
		}

		replacement := newInboundFlow(ctx, meta.GlobalID)
		next := &Session{
			parent: w.carrier, ID: s.ID, phase: outputStarting,
			transferType: protocol.TransferTypePacket, flow: replacement,
		}
		replacement.binding = next
		XUDPManager.Lock()
		x.access.Lock()
		w.Lock()
		live := !w.Closed() && s.phase == outputStarting &&
			w.sessions[s.ID] == s && x.binding == s
		if !live {
			s.closeLocked(x, false, false)
			w.Unlock()
			x.access.Unlock()
			XUDPManager.Unlock()
			buf.ReleaseMulti(data)
			s.abort()
			return nil
		}
		current := XUDPManager.Map[meta.GlobalID]
		replaced := current == x || current == nil
		s.closeLocked(x, false, false) // retire provisional identity without END
		if replaced {
			x.responseErr = io.ErrClosedPipe
			XUDPManager.Map[meta.GlobalID] = replacement
			w.invalidateUnknownLocked(next.ID)
			w.sessions[next.ID] = next
		}
		w.Unlock()
		x.access.Unlock()
		XUDPManager.Unlock()
		x.expire()
		if !replaced {
			break
		}
		s, x, fresh = next, replacement, true
	}
	if err != nil {
		buf.ReleaseMulti(data)
	}
	XUDPManager.Lock()
	x.access.Lock()
	w.Lock()
	admitted := !w.Closed() && XUDPManager.Map[meta.GlobalID] == x && x.binding == s &&
		w.sessions[s.ID] == s && s.phase == outputStarting
	if admitted {
		w.count++
		if x.responseErr == nil || len(x.response) != 0 {
			s.phase = outputOpen
			w.active++
		} else {
			s.closeLocked(x, x.responseErr == io.ErrClosedPipe, true)
		}
		x.notify()
		w.scheduleLocked(s)
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
