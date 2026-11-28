package proxy

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
)

// DispatchInboundStream transfers ownership of the parsed stream and its
// optional first record to one synchronous route.
func DispatchInboundStream(ctx context.Context, conn net.Conn, p policy.Session, dispatcher routing.Dispatcher, dest net.Destination, reader buf.Reader, writer buf.Writer, first buf.MultiBuffer) error {
	ctx, cancel := context.WithCancel(policy.ContextWithBufferPolicy(ctx, p.Buffer))
	readCtx, stopRead := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, p.Timeouts.ConnectionIdle)
	if !first.IsEmpty() {
		timer.Update()
	}
	in := &inboundStreamReader{
		ctx: readCtx, reader: reader, first: first, timer: timer, downlinkOnly: p.Timeouts.DownlinkOnly, cancel: cancel,
		ready: signal.NewNotifier(), space: signal.NewNotifier(), done: make(chan struct{}),
		bytes: int64(first.Len()), attempted: int64(first.Len()), limit: int64(p.Buffer.PerConnection),
		interrupt: func() {
			stopRead()
			// The handler retires its reader even on a graceful response close.
			// Directional interruption leaves the accepted responses to the sender.
			conn.SetReadDeadline(time.Now())
		},
	}
	out := &inboundStreamWriter{
		ctx: ctx, writer: writer, timer: timer, uplinkOnly: p.Timeouts.UplinkOnly,
		cancel: cancel, limit: int64(p.Buffer.PerConnection), done: make(chan struct{}),
	}
	out.ready.L = &out.mu
	closed := make(chan struct{})
	stopClose := context.AfterFunc(ctx, func() {
		defer close(closed)
		out.wake()
		conn.Close()
	})
	go in.receive()
	go func() {
		defer close(out.done)
		out.err = out.send()
	}()
	defer func() {
		timer.SetTimeout(0)
		cancel()
		if stopClose() {
			out.wake()
			conn.Close()
		} else {
			<-closed
		}
		<-out.done
		in.release()
	}()

	if err := dispatcher.DispatchLink(ctx, dest, &transport.Link{Reader: in, Writer: out}); err != nil {
		return err
	}
	out.Close()
	<-out.done
	return out.err
}

// One carrier decoder measures actual input even while the outbound opens or
// its peer blocks a write. The route takes decoded batches from that owner.
type inboundStreamReader struct {
	ctx          context.Context
	reader       buf.Reader
	timer        *signal.ActivityTimer
	downlinkOnly time.Duration
	cancel       context.CancelFunc
	interrupt    func()

	mu     sync.Mutex
	ready  *signal.Notifier
	space  *signal.Notifier
	done   chan struct{}
	first  buf.MultiBuffer
	queued buf.MultiBuffer
	bytes  int64
	limit  int64
	err    error
	closed bool

	bound          bool
	counter        stats.Counter
	attempted      int64
	nestedCounters []stats.Counter
}

func (r *inboundStreamReader) SetUplinkCounter(counter stats.Counter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	if !r.bound {
		r.bound = true
		r.counter = counter
		if counter != nil && r.attempted != 0 {
			counter.Add(r.attempted)
		}
		r.attempted = 0
	} else if counter != nil {
		r.nestedCounters = append(r.nestedCounters, counter)
	}
}

func (r *inboundStreamReader) Interrupt() {
	r.interrupt()
}

func (r *inboundStreamReader) receive() {
	defer close(r.done)
	for r.ctx.Err() == nil {
		mb, err := r.reader.ReadMultiBuffer()
		size := int64(mb.Len())
		if size != 0 {
			r.timer.Update()
		}

		r.mu.Lock()
		if size != 0 {
			if !r.bound {
				r.attempted += size
			} else if r.counter != nil {
				r.counter.Add(size)
			}

			// The decoder owns the attempted batch while the existing soft
			// byte limit prevents it from admitting another one.
			for r.limit >= 0 && r.bytes > r.limit && r.ctx.Err() == nil {
				r.mu.Unlock()
				select {
				case <-r.space.Wait():
				case <-r.ctx.Done():
				}
				r.mu.Lock()
			}
			if r.ctx.Err() == nil {
				r.bytes += size
				r.queued, mb = buf.MergeMulti(r.queued, mb)
			}
		}
		r.err = err
		r.mu.Unlock()
		buf.ReleaseMulti(mb)

		if err != nil && r.ctx.Err() == nil {
			if errors.Cause(err) == io.EOF {
				r.timer.SetTimeout(r.downlinkOnly)
			} else {
				r.cancel()
			}
		}
		r.ready.Signal()
		if err != nil {
			return
		}
	}
}

func (r *inboundStreamReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.read(nil)
}

func (r *inboundStreamReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	return r.read(timer.C)
}

func (r *inboundStreamReader) read(timeout <-chan time.Time) (buf.MultiBuffer, error) {
	for {
		r.mu.Lock()
		if r.closed || r.ctx.Err() != nil {
			r.mu.Unlock()
			return nil, io.ErrClosedPipe
		}
		mb := r.first
		if mb != nil {
			r.first = nil
		} else {
			mb, r.queued = r.queued, nil
		}
		if mb != nil {
			size := int64(mb.Len())
			r.bytes -= size
			for _, counter := range r.nestedCounters {
				counter.Add(size)
			}
			r.mu.Unlock()
			r.space.Signal()
			return mb, nil
		}
		err := r.err
		r.mu.Unlock()
		if err != nil {
			return nil, err
		}

		select {
		case <-r.ctx.Done():
			return nil, io.ErrClosedPipe
		case <-timeout:
			return nil, buf.ErrReadTimeout
		case <-r.ready.Wait():
		case <-r.done:
		}
	}
}

func (r *inboundStreamReader) release() {
	<-r.done
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.first = buf.ReleaseMulti(r.first)
	r.queued = buf.ReleaseMulti(r.queued)
}

// One sender writes the actual carrier. Shared Mux readers hand off responses
// within the connection's buffer policy without waiting for this socket.
type inboundStreamWriter struct {
	ctx    context.Context
	writer buf.Writer
	timer  *signal.ActivityTimer
	cancel context.CancelFunc

	mu         sync.Mutex
	ready      sync.Cond
	pending    buf.MultiBuffer
	bytes      int64
	limit      int64
	closed     bool
	uplinkOnly time.Duration

	done chan struct{}
	err  error
}

func (w *inboundStreamWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if mb.IsEmpty() {
		buf.ReleaseMulti(mb)
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for !w.closed && w.ctx.Err() == nil && w.limit >= 0 && w.bytes > w.limit {
		w.ready.Wait()
	}
	if w.closed || w.ctx.Err() != nil {
		buf.ReleaseMulti(mb)
		return io.ErrClosedPipe
	}

	w.bytes += int64(mb.Len())
	if w.pending == nil {
		w.pending = mb
	} else {
		w.pending, _ = buf.MergeMulti(w.pending, mb)
	}
	w.ready.Broadcast()
	return nil
}

func (w *inboundStreamWriter) Close() error {
	w.mu.Lock()
	w.closed = true
	w.ready.Broadcast()
	w.mu.Unlock()
	return nil
}

func (w *inboundStreamWriter) Interrupt() {
	w.cancel()
	w.wake()
}

func (w *inboundStreamWriter) wake() {
	w.mu.Lock()
	w.ready.Broadcast()
	w.mu.Unlock()
}

func (w *inboundStreamWriter) send() error {
	defer func() {
		w.mu.Lock()
		w.pending = buf.ReleaseMulti(w.pending)
		w.mu.Unlock()
	}()
	for {
		w.mu.Lock()
		for !w.closed && w.pending == nil && w.ctx.Err() == nil {
			w.ready.Wait()
		}
		if w.ctx.Err() != nil {
			w.mu.Unlock()
			return nil
		}
		pending := w.pending
		w.pending, w.bytes = nil, 0
		w.ready.Broadcast()
		w.mu.Unlock()

		if pending == nil {
			if err := common.Close(w.writer); err != nil {
				w.Interrupt()
				return err
			}
			w.timer.SetTimeout(w.uplinkOnly)
			return nil
		}
		w.timer.Update()
		if err := w.writer.WriteMultiBuffer(pending); err != nil {
			aborted := w.ctx.Err() != nil
			w.Interrupt()
			if aborted {
				return nil
			}
			return err
		}
	}
}
