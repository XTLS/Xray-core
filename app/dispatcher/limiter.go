package dispatcher

import (
	"context"
	"io"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
)

// RateLimitedWriter wraps a buf.Writer with rate limiting using golang.org/x/time/rate
type RateLimitedWriter struct {
	Writer  buf.Writer
	Counter stats.Counter
	limiter *rate.Limiter

	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
}

// NewRateLimitedWriter creates a rate-limited writer.
func NewRateLimitedWriter(w buf.Writer, limiter *rate.Limiter, counter stats.Counter) *RateLimitedWriter {
	ctx, cancel := context.WithCancel(context.Background())

	return &RateLimitedWriter{
		Writer:  w,
		Counter: counter,
		limiter: limiter,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// WriteMultiBuffer implements buf.Writer with rate limiting
func (w *RateLimitedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		buf.ReleaseMulti(mb)
		return io.ErrClosedPipe
	}
	w.mu.Unlock()

	if w.limiter != nil && w.limiter.Limit() > 0 {
		size := int(mb.Len())
		burst := w.limiter.Burst()
		for size > 0 {
			n := size
			if n > burst {
				n = burst
			}
			if err := w.limiter.WaitN(w.ctx, n); err != nil {
				buf.ReleaseMulti(mb)
				return err
			}
			size -= n
		}
	}

	if w.Counter != nil {
		w.Counter.Add(int64(mb.Len()))
	}
	return w.Writer.WriteMultiBuffer(mb)
}

// Close implements common.Closable
func (w *RateLimitedWriter) Close() error {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		w.cancel()
	}
	w.mu.Unlock()
	return common.Close(w.Writer)
}

// Interrupt implements common.Interruptible
func (w *RateLimitedWriter) Interrupt() {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		w.cancel()
	}
	w.mu.Unlock()
	common.Interrupt(w.Writer)
}

// RateLimitedReader wraps a buf.Reader with rate limiting using golang.org/x/time/rate
type RateLimitedReader struct {
	Reader  buf.Reader
	Counter stats.Counter
	limiter *rate.Limiter

	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
}

// NewRateLimitedReader creates a rate-limited reader.
func NewRateLimitedReader(r buf.Reader, limiter *rate.Limiter, counter stats.Counter) *RateLimitedReader {
	ctx, cancel := context.WithCancel(context.Background())

	return &RateLimitedReader{
		Reader:  r,
		Counter: counter,
		limiter: limiter,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// ReadMultiBuffer implements buf.Reader with rate limiting
func (r *RateLimitedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, io.ErrClosedPipe
	}
	r.mu.Unlock()

	mb, err := r.Reader.ReadMultiBuffer()
	if err != nil {
		return mb, err
	}

	size := int(mb.Len())
	if r.limiter != nil && r.limiter.Limit() > 0 && size > 0 {
		burst := r.limiter.Burst()
		for size > 0 {
			n := size
			if n > burst {
				n = burst
			}
			if waitErr := r.limiter.WaitN(r.ctx, n); waitErr != nil {
				buf.ReleaseMulti(mb)
				return nil, waitErr
			}
			size -= n
		}
	}

	if r.Counter != nil {
		r.Counter.Add(int64(mb.Len()))
	}
	return mb, nil
}

// ReadMultiBufferTimeout implements buf.TimeoutReader with rate limiting
func (r *RateLimitedReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, io.ErrClosedPipe
	}
	r.mu.Unlock()

	var mb buf.MultiBuffer
	var err error

	if tr, ok := r.Reader.(buf.TimeoutReader); ok {
		mb, err = tr.ReadMultiBufferTimeout(timeout)
	} else {
		mb, err = r.Reader.ReadMultiBuffer()
	}

	if err != nil {
		return mb, err
	}

	size := int(mb.Len())
	if r.limiter != nil && r.limiter.Limit() > 0 && size > 0 {
		burst := r.limiter.Burst()
		for size > 0 {
			n := size
			if n > burst {
				n = burst
			}
			if waitErr := r.limiter.WaitN(r.ctx, n); waitErr != nil {
				buf.ReleaseMulti(mb)
				return nil, waitErr
			}
			size -= n
		}
	}

	if r.Counter != nil {
		r.Counter.Add(int64(mb.Len()))
	}
	return mb, nil
}

// Interrupt implements common.Interruptible
func (r *RateLimitedReader) Interrupt() {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		r.cancel()
	}
	r.mu.Unlock()
	common.Interrupt(r.Reader)
}

// Close implements common.Closable
func (r *RateLimitedReader) Close() error {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		r.cancel()
	}
	r.mu.Unlock()
	return common.Close(r.Reader)
}
