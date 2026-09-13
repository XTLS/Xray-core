package splithttp

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

const (
	maxDownlinkReconnects  = 5
	downlinkReconnectDelay = 250 * time.Millisecond
)

// resumableDownlink hides stream-down boundaries from the tunneled connection,
// reopening the request at the offset already received whenever it is cut.
type resumableDownlink struct {
	ctx         context.Context
	open        func(ctx context.Context, offset uint64) (io.ReadCloser, error)
	rotateAfter func() time.Duration

	access   sync.Mutex
	current  io.ReadCloser
	received uint64
	closed   bool
	started  bool
	gen      uint64

	windowStart time.Time
	windowCount int
}

func newResumableDownlink(ctx context.Context, rotateAfter func() time.Duration,
	open func(ctx context.Context, offset uint64) (io.ReadCloser, error),
) *resumableDownlink {
	return &resumableDownlink{ctx: ctx, open: open, rotateAfter: rotateAfter}
}

func (r *resumableDownlink) Offset() uint64 {
	r.access.Lock()
	defer r.access.Unlock()
	return r.received
}

func (r *resumableDownlink) Read(p []byte) (int, error) {
	for {
		r.access.Lock()
		closed, current := r.closed, r.current
		r.access.Unlock()
		if closed {
			return 0, io.EOF
		}

		if current == nil {
			if err := r.reconnect(); err != nil {
				return 0, err
			}
			continue
		}

		n, err := current.Read(p)
		if n > 0 {
			r.access.Lock()
			r.received += uint64(n)
			r.access.Unlock()
			return n, nil
		}
		if err == nil {
			continue
		}

		rejected, supported, finished := false, false, false
		if c, ok := current.(interface {
			Rejected() bool
			Supported() bool
			Finished() bool
		}); ok {
			rejected, supported, finished = c.Rejected(), c.Supported(), c.Finished()
		}
		r.dropCurrent(current)
		if r.stopped() || finished {
			return 0, io.EOF
		}
		if rejected {
			return 0, errors.New("XHTTP downlink resume refused by the server at offset ", r.Offset())
		}
		if !supported {
			// Reached only once the response arrived, so an unacknowledged
			// server means resume is not available and the connection ends as
			// it would without the feature.
			errors.LogWarning(r.ctx, "XHTTP: server did not acknowledge scDownlinkResume, not resuming")
			return 0, io.EOF
		}
		if err := r.reconnect(); err != nil {
			return 0, err
		}
	}
}

func (r *resumableDownlink) stopped() bool {
	r.access.Lock()
	closed := r.closed
	r.access.Unlock()
	return closed || r.ctx.Err() != nil
}

func (r *resumableDownlink) dropCurrent(current io.ReadCloser) {
	r.access.Lock()
	if r.current == current {
		r.current = nil
		r.gen++
	}
	r.access.Unlock()
	current.Close()
}

func (r *resumableDownlink) reconnect() error {
	var lastErr error
	for attempt := 0; attempt < maxDownlinkReconnects; attempt++ {
		if r.stopped() {
			return io.EOF
		}
		if attempt > 0 {
			select {
			case <-time.After(downlinkReconnectDelay):
			case <-r.ctx.Done():
				return io.EOF
			}
		}

		r.access.Lock()
		offset := r.received
		r.access.Unlock()

		reader, err := r.open(r.ctx, offset)
		if err != nil {
			lastErr = err
			continue
		}

		r.access.Lock()
		if r.closed {
			r.access.Unlock()
			reader.Close()
			return io.EOF
		}
		r.current = reader
		r.gen++
		gen := r.gen
		r.access.Unlock()

		r.armRotation(gen, reader)
		r.access.Lock()
		resumed := r.started
		r.started = true
		r.access.Unlock()
		if resumed {
			errors.LogInfo(r.ctx, "XHTTP downlink resumed at offset ", offset, ", attempts ", attempt+1)
		}
		return nil
	}

	if lastErr == nil {
		lastErr = errors.New("downlink could not be reopened")
	}
	return errors.New("XHTTP downlink resume failed").Base(lastErr)
}

// armRotation closes the stream before a middlebox does, which Read turns into
// a reconnect.
func (r *resumableDownlink) armRotation(gen uint64, reader io.ReadCloser) {
	if r.rotateAfter == nil {
		return
	}
	after := r.rotateAfter()
	if after <= 0 {
		return
	}
	time.AfterFunc(after, func() {
		r.access.Lock()
		stale := r.gen != gen || r.closed
		r.access.Unlock()
		if !stale {
			reader.Close()
		}
	})
}

func (r *resumableDownlink) Close() error {
	r.access.Lock()
	if r.closed {
		r.access.Unlock()
		return nil
	}
	r.closed = true
	current := r.current
	r.current = nil
	r.gen++
	r.access.Unlock()

	if current != nil {
		return current.Close()
	}
	return nil
}
