package exchange

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/signal"
)

const aheadChunkSize = 16 * 1024

var aheadBuffers = sync.Pool{New: func() any { return new([aheadChunkSize]byte) }}

// Queue ownership retains the original allocation while a partial read advances.
type aheadChunk struct {
	storage    *[aheadChunkSize]byte
	start, end int
}

// Ahead preserves independent producer completion. Zero permits one accepted
// chunk; negative explicitly permits unlimited buffering, as native policy does.
// One consumer owns Read/ReadTimeout; sniffing, preparation and transfer pass
// that ownership sequentially. Stop and Join may run concurrently with Read.
type Ahead struct {
	mu                    sync.Mutex
	queue                 []aheadChunk
	size                  int64
	terminal              error
	readReady, writeReady *signal.Notifier
	done, finished        chan struct{}
	ctx                   context.Context
	cancel                context.CancelFunc
}

func NewAhead(parent context.Context, reader io.Reader, capacity int32) (*Ahead, error) {
	ctx, cancel := context.WithCancel(parent)
	a := &Ahead{ctx: ctx, cancel: cancel, readReady: signal.NewNotifier(), writeReady: signal.NewNotifier(), done: make(chan struct{}), finished: make(chan struct{})}
	go func() {
		defer close(a.finished)
		empty := 0
		for {
			p := aheadBuffers.Get().(*[aheadChunkSize]byte)
			n, err := reader.Read(p[:])
			if n == 0 && err == nil {
				empty++
				if empty >= 100 {
					err = io.ErrNoProgress
				}
			} else {
				empty = 0
			}
			// Data+EOF is published after payload acceptance. Pure EOF needs no space.
			for {
				a.mu.Lock()
				if ctx.Err() != nil {
					a.mu.Unlock()
					aheadBuffers.Put(p)
					return
				}
				if n == 0 || capacity < 0 || a.size <= int64(capacity) {
					break
				}
				a.mu.Unlock()
				select {
				case <-a.writeReady.Wait():
				case <-ctx.Done():
					aheadBuffers.Put(p)
					return
				}
			}
			if n > 0 {
				a.queue = append(a.queue, aheadChunk{storage: p, end: n})
				a.size += int64(n)
			} else {
				aheadBuffers.Put(p)
			}
			if err != nil {
				a.terminal = err
			}
			a.readReady.Signal()
			a.mu.Unlock()
			if err != nil {
				if err == io.EOF {
					close(a.done)
				}
				return
			}
		}
	}()
	return a, nil
}
func (a *Ahead) InputDone() <-chan struct{} { return a.done }
func (a *Ahead) Stop()                      { a.cancel() }

// Join keeps accepted data readable after normal producer EOF. After abort it
// releases queued chunks only when the producer has stopped. Read copies under
// the same mutex, so no pooled block remains in use by a partial consumer read.
func (a *Ahead) Join() {
	<-a.finished
	if a.ctx.Err() == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.queue {
		aheadBuffers.Put(a.queue[i].storage)
		a.queue[i] = aheadChunk{}
	}
	a.queue = nil
	a.size = 0
}
func (a *Ahead) Read(p []byte) (int, error)                         { return a.read(p, 0) }
func (a *Ahead) ReadTimeout(p []byte, d time.Duration) (int, error) { return a.read(p, d) }
func (a *Ahead) read(p []byte, d time.Duration) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	var timeout <-chan time.Time
	if d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		timeout = t.C
	}
	for {
		a.mu.Lock()
		if a.ctx.Err() != nil {
			a.mu.Unlock()
			return 0, a.ctx.Err()
		}
		if len(a.queue) > 0 {
			chunk := &a.queue[0]
			n := copy(p, chunk.storage[chunk.start:chunk.end])
			chunk.start += n
			a.size -= int64(n)
			if chunk.start == chunk.end {
				aheadBuffers.Put(chunk.storage)
				a.queue[0] = aheadChunk{}
				a.queue = a.queue[1:]
			}
			a.writeReady.Signal()
			a.mu.Unlock()
			return n, nil
		}
		if a.terminal != nil {
			err := a.terminal
			a.mu.Unlock()
			return 0, err
		}
		a.mu.Unlock()
		select {
		case <-a.readReady.Wait():
		case <-a.ctx.Done():
			return 0, a.ctx.Err()
		case <-timeout:
			return 0, readTimeout{}
		}
	}
}

type readTimeout struct{}

func (readTimeout) Error() string { return "read timeout" }
func (readTimeout) Timeout() bool { return true }
