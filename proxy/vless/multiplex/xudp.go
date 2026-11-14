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

// inboundFlow owns native route input and response custody. A nonzero GlobalID
// retains that custody across replaceable wire identities. No physical
// I/O or Session closure occurs under access. Nested locks: registry, map, flow.
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
	Status                  uint64
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

// publishBinding requires access and a persistent association. Start the response
// drain before first-packet admission, which can wait for native request capacity.
func (x *inboundFlow) publishBinding(s *Session) {
	x.binding = s
	go x.emit(s)
	x.notify()
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
		if x.requestErr != nil || x.binding != binding ||
			(x.Status == Initializing && x.GlobalID != [8]byte{} && x.responseErr != nil && len(x.response) == 0) {
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

func (w *flowOutput) Interrupt()    { w.finish(true) }
func (x *inboundFlow) Close() error { x.finish(false); return nil }
func (x *inboundFlow) finish(abort bool) {
	x.access.Lock()
	if x.responseErr == nil {
		x.responseErr = io.EOF
	}
	if abort && x.responseErr != io.ErrClosedPipe {
		x.responseErr = io.ErrClosedPipe
		x.response = buf.ReleaseMulti(x.response)
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

// Native response admission is the append, not invocation of this method.
// Close rejects/wakes a capacity-blocked writer while preserving accepted data.
func (x *inboundFlow) WriteMultiBuffer(data buf.MultiBuffer) error {
	x.access.Lock()
	defer x.access.Unlock()
	for x.responseErr == nil && x.limit >= 0 && x.response.Len() > x.limit {
		x.responseWake.Wait()
	}
	if x.responseErr != nil {
		buf.ReleaseMulti(data)
		return io.ErrClosedPipe
	}
	if len(x.response) == 0 {
		x.response = data
	} else {
		x.response, _ = buf.MergeMulti(x.response, data)
	}
	x.responseWake.Broadcast()
	return nil
}

// lockedBufferedWriter borrows the existing gate synchronously; it owns no
// mutex or buffer and may only be invoked while that gate is locked.
type lockedBufferedWriter buf.BufferedWriter

func (w *lockedBufferedWriter) WriteMultiBuffer(data buf.MultiBuffer) error {
	return (*buf.BufferedWriter)(w).WriteMultiBufferLocked(data)
}

// The binding emitter owns DATA and END. It claims response payload only
// after acquiring the physical gate, and never holds a flow lock during I/O.
func (x *inboundFlow) emit(s *Session) {
	c := s.sender
	defer func() {
		s.parent.RLock()
		ownsEnd, failed := s.closed && s.flow == x, s.failed
		s.parent.RUnlock()
		if ownsEnd {
			defer s.endWritten()
			if !c.Closed() {
				writer := NewResponseWriter(s.ID, c, s.transferType)
				writer.hasError = failed
				writer.Close()
			}
		}
	}()
	gate := c.link.Writer.(*buf.BufferedWriter)
	for {
		x.access.Lock()
		for x.binding == s && len(x.response) == 0 && (x.responseErr == nil || x.Status == Initializing) {
			x.responseWake.Wait()
		}
		if x.binding != s {
			x.access.Unlock()
			return
		}
		if len(x.response) == 0 {
			failed := x.responseErr == io.ErrClosedPipe
			x.access.Unlock()
			s.closeOwned(failed, x)
			continue
		}
		x.access.Unlock()

		gate.Lock()
		x.access.Lock()
		if x.binding != s || c.Closed() {
			x.access.Unlock()
			gate.Unlock()
			return
		}
		if x.responseErr == io.ErrClosedPipe {
			x.access.Unlock()
			gate.Unlock()
			continue
		}
		var data buf.MultiBuffer
		if s.transferType == protocol.TransferTypeStream {
			for n := 0; n < 4 && !x.response.IsEmpty(); n++ {
				var chunk buf.MultiBuffer
				x.response, chunk = buf.SplitSize(x.response, 8*1024)
				data = append(data, chunk...)
			}
		} else {
			n := min(4, len(x.response))
			data = x.response[:n:n]
			x.response = x.response[n:]
		}
		if len(x.response) == 0 {
			x.response = nil
		}
		if x.Status == Initializing && x.responseErr != nil && len(x.response) == 0 {
			x.notify()
		} else {
			x.responseWake.Broadcast()
		}
		x.access.Unlock()
		writer := NewResponseWriter(s.ID, (*lockedBufferedWriter)(gate), s.transferType)
		err := writer.WriteMultiBuffer(data)
		gate.Unlock()
		if err != nil {
			c.closeCause(err)
			return
		}
	}
}

func (w *ServerWorker) bindXUDP(ctx context.Context, meta *FrameMetadata, reader *buf.BufferedReader) error {
	data, err := readPacket(reader, meta.Target)
	if err != nil {
		return err
	}
	XUDPManager.Lock()
	x := XUDPManager.Map[meta.GlobalID]
	fresh := x == nil
	if fresh {
		x = newInboundFlow(ctx, meta.GlobalID)
		XUDPManager.Map[meta.GlobalID] = x
	}
	if !fresh && x.Status == Initializing {
		XUDPManager.Unlock()
		buf.ReleaseMulti(data)
		errors.LogWarningInner(ctx, errors.New("conflict"), "XUDP hit ", meta.GlobalID)
		return nil
	}
	x.access.Lock()
	x.Status = Initializing
	previous := x.binding
	x.access.Unlock()
	XUDPManager.Unlock()
	if previous != nil {
		previous.Close()
	}
	s := &Session{
		parent: w.sessionManager, ID: meta.SessionID, transferType: protocol.TransferTypePacket,
		flow: x, sender: w.carrier,
	}
	stopProvisional := context.AfterFunc(w.carrier.ctx, func() { s.Close() })
	defer stopProvisional()
	ctx = session.ContextWithTimeoutOnly(ctx, true)
	dest := meta.Target
	for {
		w.sessionManager.Lock()
		XUDPManager.Lock()
		x.access.Lock()
		if !s.closed && XUDPManager.Map[meta.GlobalID] == x {
			x.publishBinding(s)
		}
		x.access.Unlock()
		XUDPManager.Unlock()
		w.sessionManager.Unlock()
		if fresh {
			go w.dispatchFlow(ctx, dest, x)
		}
		err = x.accept(data, s)
		if err == nil || fresh {
			break
		}

		w.sessionManager.Lock()
		if s.closed || w.Closed() {
			XUDPManager.Lock()
			x.access.Lock()
			if XUDPManager.Map[meta.GlobalID] == x && x.Status == Initializing {
				x.Expire, x.Status = time.Now().Add(time.Minute), Expiring
			}
			x.notify()
			x.access.Unlock()
			XUDPManager.Unlock()
			w.sessionManager.Unlock()
			buf.ReleaseMulti(data)
			s.Close()
			return nil
		}
		replacement := newInboundFlow(ctx, meta.GlobalID)
		XUDPManager.Lock()
		x.access.Lock()
		if x.binding == s {
			x.binding = nil
			x.notify()
		}
		current := XUDPManager.Map[meta.GlobalID]
		replaced := current == x || current == nil
		if replaced {
			if x.Status == Initializing {
				x.Expire, x.Status = time.Now().Add(time.Minute), Expiring
			}
			XUDPManager.Map[meta.GlobalID] = replacement
			s.flow = replacement
		}
		x.access.Unlock()
		XUDPManager.Unlock()
		w.sessionManager.Unlock()
		x.expire()
		if !replaced {
			break
		}
		x, fresh = replacement, true
	}
	if err != nil {
		buf.ReleaseMulti(data)
	}
	w.sessionManager.Lock()
	XUDPManager.Lock()
	x.access.Lock()
	admitted := XUDPManager.Map[meta.GlobalID] == x && x.binding == s && w.sessionManager.add(s)
	if admitted {
		x.Status = Active
	} else if XUDPManager.Map[meta.GlobalID] == x && x.Status == Initializing {
		x.Expire, x.Status = time.Now().Add(time.Minute), Expiring
	}
	x.notify()
	x.access.Unlock()
	XUDPManager.Unlock()
	w.sessionManager.Unlock()
	if !admitted {
		s.Close()
		return errors.New("failed to add new session")
	}
	return nil
}
