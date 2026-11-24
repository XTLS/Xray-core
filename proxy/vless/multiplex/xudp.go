package multiplex

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
)

// inboundFlow owns native route input and persistent binding state. Its response
// packet response mailbox retains native bytes until the physical sender claims them.
// Locks nest association map -> flow -> one carrier; I/O is outside them.
type inboundFlow struct {
	access sync.Mutex

	requestWake, responseWake sync.Cond
	request, response         buf.MultiBuffer
	requestErr, responseErr   error
	uplinkCounter             stats.Counter
	uplinkPending             int64
	uplinkBound               bool
	limit                     int32
	binding                   *Session
	GlobalID                  [8]byte
	Expire                    time.Time
}

func newInboundFlow(ctx context.Context, id [8]byte) *inboundFlow {
	x := &inboundFlow{limit: policy.BufferPolicyFromContext(ctx).PerConnection, GlobalID: id}
	x.requestWake.L, x.responseWake.L = &x.access, &x.access
	return x
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
	if abort {
		x.responseErr = io.ErrClosedPipe
		x.response = buf.ReleaseMulti(x.response)
	} else if x.responseErr == nil {
		x.responseErr = io.EOF
	}
	if s := x.binding; s != nil {
		c := s.parent
		c.Lock()
		if abort && s.phase == outputOpen {
			s.closeLocked(x, true, true)
		} else {
			c.scheduleLocked(s)
		}
		c.Unlock()
	}
	x.responseWake.Broadcast()
	x.access.Unlock()
}

func (x *inboundFlow) expire() {
	x.access.Lock()
	if x.requestErr == nil {
		x.requestErr = io.EOF
		x.requestWake.Broadcast()
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

// packetReady is checked with the flow and carrier locked.
func (s *Session) packetReady() bool {
	x := s.flow
	return x != nil && x.binding == s &&
		(s.phase == outputOpen && (len(x.response) != 0 || x.responseErr != nil) ||
			s.phase == outputStarting && x.requestErr == nil && len(x.response) != 0)
}

// One gated actor claims packet data or retires one exact terminal identity.
// It returns custody only; the sender encodes after both logical locks release.
func (c *carrier) responseTurn(id uint16, s *Session) (buf.MultiBuffer, bool) {
	if s != nil && s.flow != nil {
		s.flow.access.Lock()
		defer s.flow.access.Unlock()
	}
	c.Lock()
	defer c.Unlock()
	if c.Closed() {
		return nil, false
	}
	if s == nil {
		return nil, c.invalidateUnknownLocked(id)
	}
	if c.sessions[id] != s {
		return nil, false
	}
	x := s.flow
	ready := s.packetReady()
	if ready && len(x.response) == 0 {
		s.closeLocked(x, x.responseErr == io.ErrClosedPipe, true)
	}
	if s.phase == outputDone {
		delete(c.ready, s.ID)
		delete(c.sessions, s.ID)
		return nil, true
	}
	if !ready {
		delete(c.ready, s.ID)
		return nil, false
	}
	n := min(4, len(x.response))
	data := x.response[:n:n]
	x.response = x.response[n:]
	if len(x.response) == 0 {
		x.response = nil
	}
	x.responseWake.Broadcast()
	// A terminal follow-up cannot run until this DATA turn completes physically.
	if !s.packetReady() {
		delete(c.ready, s.ID)
	}
	return data, false
}

func (w *ServerWorker) bindXUDP(ctx context.Context, meta *FrameMetadata, reader *buf.BufferedReader) error {
	data, err := readPacket(reader, meta.Target)
	if err != nil {
		return err
	}
	ctx = session.ContextWithTimeoutOnly(ctx, true)
	XUDPManager.Lock()
	for {
		x := XUDPManager.Map[meta.GlobalID]
		fresh := x == nil
		if fresh {
			x = newInboundFlow(ctx, meta.GlobalID)
		}
		x.access.Lock()
		if previous := x.binding; previous != nil {
			previous.parent.Lock()
			if previous.phase == outputStarting {
				previous.parent.Unlock()
				x.access.Unlock()
				XUDPManager.Unlock()
				buf.ReleaseMulti(data)
				errors.LogWarningInner(ctx, errors.New("conflict"), "XUDP hit ", meta.GlobalID)
				return nil
			}
			previous.closeLocked(x, true, true)
			previous.parent.Unlock()
		}
		w.Lock()
		if w.Closed() || w.sessions[meta.SessionID] != nil {
			w.Unlock()
			x.access.Unlock()
			XUDPManager.Unlock()
			buf.ReleaseMulti(data)
			return errors.New("failed to add new session")
		}
		s := &Session{
			parent: w.carrier, ID: meta.SessionID, phase: outputStarting,
			target: net.Destination{Network: net.Network_UDP}, flow: x,
		}
		w.invalidateUnknownLocked(s.ID)
		w.sessions[s.ID] = s
		XUDPManager.Map[meta.GlobalID] = x
		x.binding, x.Expire = s, time.Time{}
		w.scheduleLocked(s)
		w.Unlock()
		x.access.Unlock()
		XUDPManager.Unlock()
		if fresh {
			go w.dispatchFlow(ctx, meta.Target, x, &flowOutput{x})
		}
		err = x.accept(data, s)

		XUDPManager.Lock()
		x.access.Lock()
		w.Lock()
		live := !w.Closed() && w.sessions[s.ID] == s && x.binding == s && s.phase == outputStarting
		current := XUDPManager.Map[meta.GlobalID]
		restart := err != nil && !fresh
		retry := restart && live && (current == x || current == nil)
		admitted := live && current == x
		if restart {
			s.closeLocked(x, false, false)
			if retry {
				x.responseErr = io.ErrClosedPipe
				x.response = buf.ReleaseMulti(x.response)
				x.responseWake.Broadcast()
				delete(XUDPManager.Map, meta.GlobalID)
			}
		} else if admitted {
			w.count++
			if x.responseErr == nil || len(x.response) != 0 {
				s.phase = outputOpen
				w.active++
			} else {
				s.closeLocked(x, x.responseErr == io.ErrClosedPipe, true)
			}
			w.scheduleLocked(s)
		}
		w.Unlock()
		x.access.Unlock()
		if retry {
			// Keep the manager lock until the replacement is registered.
			continue
		}
		XUDPManager.Unlock()
		if err != nil {
			buf.ReleaseMulti(data)
		}
		if restart {
			if !live {
				return nil
			}
			x.expire()
		}
		if restart || !admitted {
			s.abort()
			return errors.New("failed to add new session")
		}
		return nil
	}
}
