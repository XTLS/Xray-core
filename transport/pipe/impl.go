package pipe

import (
	"errors"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/signal/done"
)

type state byte

const (
	open state = iota
	closed
	errord
)

type pipeOption struct {
	limit           int32 // maximum buffer size in bytes
	discardOverflow bool
}

func (o *pipeOption) isFull(curSize int32) bool {
	return o.limit >= 0 && curSize > o.limit
}

type pipe struct {
	sync.Mutex
	queue       []buf.MultiBuffer
	queuedBytes int32
	readSignal  *signal.Notifier
	writeSignal *signal.Notifier
	done        *done.Instance
	errChan     chan error
	option      pipeOption
	state       state
}

var (
	errBufferFull = errors.New("buffer full")
	errSlowDown   = errors.New("slow down")
)

func (p *pipe) Len() int32 {
	p.Lock()
	defer p.Unlock()
	return p.queuedBytes
}

func (p *pipe) getState(forRead bool) error {
	switch p.state {
	case open:
		if !forRead && p.option.isFull(p.queuedBytes) {
			return errBufferFull
		}
		return nil
	case closed:
		if !forRead {
			return io.ErrClosedPipe
		}
		if p.queuedBytes > 0 {
			return nil
		}
		return io.EOF
	case errord:
		return io.ErrClosedPipe
	default:
		panic("impossible case")
	}
}

func (p *pipe) readMultiBufferInternal() (buf.MultiBuffer, error) {
	p.Lock()
	defer p.Unlock()

	if err := p.getState(true); err != nil {
		return nil, err
	}

	if len(p.queue) == 0 {
		return nil, nil
	}

	mb := p.queue[0]
	p.queue = p.queue[1:]
	for _, next := range p.queue {
		mb, _ = buf.MergeMulti(mb, next)
	}
	p.queue = nil
	p.queuedBytes = 0
	return mb, nil
}

func (p *pipe) ReadMultiBuffer() (buf.MultiBuffer, error) {
	for {
		data, err := p.readMultiBufferInternal()
		if data != nil || err != nil {
			p.writeSignal.Signal()
			return data, err
		}

		select {
		case <-p.readSignal.Wait():
		case <-p.done.Wait():
		case err = <-p.errChan:
			return nil, err
		}
	}
}

func (p *pipe) ReadMultiBufferTimeout(d time.Duration) (buf.MultiBuffer, error) {
	timer := time.NewTimer(d)
	defer timer.Stop()

	for {
		data, err := p.readMultiBufferInternal()
		if data != nil || err != nil {
			p.writeSignal.Signal()
			return data, err
		}

		select {
		case <-p.readSignal.Wait():
		case <-p.done.Wait():
		case <-timer.C:
			return nil, buf.ErrReadTimeout
		case err = <-p.errChan:
			return nil, err
		}
	}
}

func (p *pipe) writeMultiBufferInternal(mb buf.MultiBuffer) error {
	p.Lock()
	defer p.Unlock()

	if err := p.getState(false); err != nil {
		return err
	}

	if p.option.isFull(p.queuedBytes) {
		return errBufferFull
	}

	p.queue = append(p.queue, mb)
	p.queuedBytes += mb.Len()
	return nil
}

func (p *pipe) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if mb.IsEmpty() {
		return nil
	}

	for {
		err := p.writeMultiBufferInternal(mb)
		if err == nil {
			p.readSignal.Signal()
			return nil
		}

		if err == errBufferFull {
			if p.option.discardOverflow {
				buf.ReleaseMulti(mb)
				return nil
			}
			select {
			case <-p.writeSignal.Wait():
				continue
			case <-p.done.Wait():
				buf.ReleaseMulti(mb)
				return io.ErrClosedPipe
			}
		}

		buf.ReleaseMulti(mb)
		p.readSignal.Signal()
		return err
	}
}

func (p *pipe) releaseQueueLocked() {
	for _, mb := range p.queue {
		buf.ReleaseMulti(mb)
	}
	p.queue = nil
	p.queuedBytes = 0
}

func (p *pipe) Close() error {
	p.Lock()
	defer p.Unlock()

	if p.state == closed || p.state == errord {
		return nil
	}

	p.state = closed
	common.Must(p.done.Close())
	return nil
}

// Interrupt implements common.Interruptible.
func (p *pipe) Interrupt() {
	p.Lock()
	defer p.Unlock()

	if p.queuedBytes > 0 {
		p.releaseQueueLocked()
		if p.state == closed {
			p.state = errord
		}
	}

	if p.state == closed || p.state == errord {
		return
	}

	p.state = errord

	common.Must(p.done.Close())
}
