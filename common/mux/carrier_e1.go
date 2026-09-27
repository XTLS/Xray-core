package mux

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

const (
	maxNativeChildren    = 8
	childInputFrames     = 8
	maxNativeFrame       = 8 * 1024
	carrierFrameJobs     = 32
	carrierDataJobs      = 16
	maxCarrierFrameBytes = 65535 + 512 + 2
)

type carrierJob struct {
	frame   []byte
	control bool
	ack     chan error
}

// carrierFrames is the one owner of complete wire frames, including END.
// The Link writer ACK means acceptance into that writer, not remote delivery.
type carrierFrames struct {
	ctx          context.Context
	cancel       context.CancelFunc
	output       buf.Writer
	queue        chan carrierJob
	dataSlots    chan struct{}
	done         chan struct{}
	mu           sync.Mutex
	closed       bool
	submitters   sync.WaitGroup
	writeTimeout time.Duration
}

func newCarrierFrames(ctx context.Context, cancel context.CancelFunc, output buf.Writer, writeTimeout time.Duration) *carrierFrames {
	f := &carrierFrames{ctx: ctx, cancel: cancel, output: output, queue: make(chan carrierJob, carrierFrameJobs), dataSlots: make(chan struct{}, carrierDataJobs), done: make(chan struct{}), writeTimeout: writeTimeout}
	for i := 0; i < carrierDataJobs; i++ {
		f.dataSlots <- struct{}{}
	}
	go f.run()
	return f
}

func (f *carrierFrames) begin() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.ctx.Err() != nil {
		return context.Canceled
	}
	f.submitters.Add(1)
	return nil
}

func (f *carrierFrames) submit(ctx context.Context, frame []byte, control bool) error {
	if len(frame) > maxCarrierFrameBytes {
		return errors.New("MUX frame exceeds carrier bound")
	}
	if err := f.begin(); err != nil {
		return err
	}
	defer f.submitters.Done()
	job := carrierJob{frame: frame, control: control, ack: make(chan error, 1)}
	if !control {
		select {
		case <-f.dataSlots:
		case <-ctx.Done():
			return ctx.Err()
		case <-f.ctx.Done():
			return f.ctx.Err()
		}
	}
	select {
	case f.queue <- job:
	case <-ctx.Done():
		if !control {
			f.dataSlots <- struct{}{}
		}
		return ctx.Err()
	case <-f.ctx.Done():
		if !control {
			f.dataSlots <- struct{}{}
		}
		return f.ctx.Err()
	}
	select {
	case err := <-job.ack:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-f.ctx.Done():
		return f.ctx.Err()
	}
}

// tryControl never waits in the carrier decoder. A saturated control reserve
// fails the carrier rather than pinning parsing behind one child.
func (f *carrierFrames) tryControl(frame []byte) error {
	if len(frame) > maxCarrierFrameBytes {
		return errors.New("MUX control frame exceeds bound")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.ctx.Err() != nil {
		return context.Canceled
	}
	select {
	case f.queue <- carrierJob{frame: frame, control: true, ack: make(chan error, 1)}:
		return nil
	default:
		return errors.New("MUX carrier control queue full")
	}
}

func (f *carrierFrames) finishJob(job carrierJob, err error) {
	job.ack <- err
	if !job.control {
		f.dataSlots <- struct{}{}
	}
}

func (f *carrierFrames) run() {
	defer close(f.done)
	defer func() {
		f.mu.Lock()
		f.closed = true
		f.mu.Unlock()
		f.submitters.Wait()
		for {
			select {
			case job := <-f.queue:
				f.finishJob(job, context.Canceled)
			default:
				return
			}
		}
	}()
	for {
		if f.ctx.Err() != nil {
			return
		}
		select {
		case <-f.ctx.Done():
			return
		case job := <-f.queue:
			// A stalled shared sink fails the carrier. Cancellation wakes the
			// owner monitor, which closes physical I/O before joining this worker.
			expiry := time.AfterFunc(f.writeTimeout, f.cancel)
			err := f.output.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(job.frame)})
			expiry.Stop()
			f.finishJob(job, err)
			if err != nil {
				f.cancel()
				return
			}
		}
	}
}

func (f *carrierFrames) wait() { <-f.done }

type carrierFrameWriter struct{ frames *carrierFrames }

func (w carrierFrameWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	if mb.IsEmpty() {
		return nil
	}
	if mb.Len() > maxCarrierFrameBytes {
		return errors.New("MUX frame exceeds carrier bound")
	}
	frame := make([]byte, 0, mb.Len())
	for _, b := range mb {
		frame = append(frame, b.Bytes()...)
	}
	control := len(frame) > 4 && SessionStatus(frame[4]) == SessionStatusEnd
	return w.frames.submit(w.frames.ctx, frame, control)
}

var _ buf.Writer = carrierFrameWriter{}
