package xdrive

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

const (
	maxCoalescedTicks = 8

	segSuffix = ".seg"
	endSuffix = ".end"
	errSuffix = ".err"
)

func objectName(prefix string, seq int64, suffix string) string {
	return fmt.Sprintf("%s/%09d%s", prefix, seq, suffix)
}

func parseEntry(name string) (int64, bool) {
	dot := strings.LastIndexByte(name, '.')
	if dot < 0 {
		return 0, false
	}
	switch name[dot:] {
	case segSuffix, endSuffix, errSuffix:
	default:
		return 0, false
	}
	seq, err := strconv.ParseInt(name[:dot], 10, 64)
	if err != nil || seq < 0 {
		return 0, false
	}
	return seq, true
}

type walWriter struct {
	ctx     context.Context
	storage Storage
	prefix  string
	params
	sem chan struct{}
	wg  sync.WaitGroup

	mu       sync.Mutex
	buf      []byte
	seq      int64
	lastSize int
	segBytes int
	ramped   int
	held     int
	closed   bool
	err      error
}

func newWALWriter(ctx context.Context, storage Storage, prefix string, p params) *walWriter {
	w := &walWriter{
		ctx:     ctx,
		storage: storage,
		prefix:  prefix,
		params:  p,
		sem:     make(chan struct{}, p.concurrency),
	}
	// A session being set up is latency bound: small segments fit in a
	// single inline create, so start there and double up to the configured
	// size once full segments keep coming.
	w.segBytes = min(p.segmentBytes, driveInlineLimit)
	go w.flushLoop()
	return w
}

func (w *walWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, io.ErrClosedPipe
	}

	w.buf = append(w.buf, p...)
	for len(w.buf) >= w.segBytes {
		if err := w.flushLocked(); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (w *walWriter) flushLoop() {
	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.mu.Lock()
			if !w.closed && w.err == nil && len(w.buf) > 0 && w.readyToFlush() {
				w.flushLocked()
			}
			done := w.closed || w.err != nil
			w.mu.Unlock()
			if done {
				return
			}
		}
	}
}

func (w *walWriter) readyToFlush() bool {
	grew := len(w.buf) > w.lastSize
	w.lastSize = len(w.buf)

	if grew && w.held < maxCoalescedTicks {
		w.held++
		return false
	}
	w.held = 0
	return true
}

func (w *walWriter) flushLocked() error {
	if len(w.buf) == 0 {
		return nil
	}
	if w.err != nil {
		return w.err
	}

	n := len(w.buf)
	if n > w.segBytes {
		n = w.segBytes
	}
	if n == w.segBytes && w.segBytes < w.segmentBytes {
		w.ramped++
		if w.ramped >= inlineRampSegments {
			w.ramped = 0
			w.segBytes = min(w.segBytes*2, w.segmentBytes)
		}
	}

	chunk := make([]byte, n)
	copy(chunk, w.buf[:n])
	seq := w.seq
	w.seq++

	if n == len(w.buf) {
		w.buf = w.buf[:0]
	} else {
		w.buf = append(w.buf[:0], w.buf[n:]...)
	}
	w.lastSize = len(w.buf)
	w.held = 0

	w.wg.Add(1)
	go w.upload(seq, chunk)
	return nil
}

func (w *walWriter) upload(seq int64, chunk []byte) {
	defer w.wg.Done()

	select {
	case w.sem <- struct{}{}:
	case <-w.ctx.Done():
		return
	}
	defer func() { <-w.sem }()

	if err := w.storage.Put(w.ctx, objectName(w.prefix, seq, segSuffix), chunk); err != nil {
		w.mu.Lock()
		if w.err == nil {
			w.err = errors.New("failed to store segment").Base(err)
		}
		w.mu.Unlock()
		w.storage.Put(w.ctx, objectName(w.prefix, seq, errSuffix), nil)
	}
}

func (w *walWriter) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	for len(w.buf) > 0 && w.err == nil {
		w.flushLocked()
	}
	w.mu.Unlock()

	w.wg.Wait()

	w.mu.Lock()
	err, seq := w.err, w.seq
	w.mu.Unlock()

	if err != nil {
		return err
	}
	return w.storage.Put(w.ctx, objectName(w.prefix, seq, endSuffix), nil)
}

type walReader struct {
	ctx     context.Context
	storage Storage
	prefix  string
	params
	seq int64

	ch        chan []byte
	discards  chan string
	wake      chan struct{}
	holeSince time.Time

	errMu sync.Mutex
	err   error
}

func newWALReader(ctx context.Context, storage Storage, prefix string, p params) *walReader {
	r := &walReader{
		ctx:      ctx,
		storage:  storage,
		prefix:   prefix,
		params:   p,
		ch:       make(chan []byte, p.concurrency),
		discards: make(chan string, 4*p.concurrency),
		wake:     make(chan struct{}, 1),
	}
	go r.run()
	go r.discardLoop()
	return r
}

func (r *walReader) chunks() <-chan []byte {
	return r.ch
}

func (r *walReader) Wake() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *walReader) run() {
	defer close(r.ch)

	delay := r.minPollInterval
	active := time.Now()
	for {
		polled := time.Now()
		advanced, eof, err := r.poll()
		if err != nil {
			r.setErr(err)
			return
		}
		if eof {
			return
		}

		switch {
		case advanced:
			active = time.Now()
			delay = r.minPollInterval
		case time.Since(active) < r.eagerWindow:
			delay = r.minPollInterval
		default:
			delay *= 2
			if delay > r.maxPollInterval {
				delay = r.maxPollInterval
			}
		}

		timer := time.NewTimer(delay)
		select {
		case <-r.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		case <-r.wake:
			timer.Stop()
			active = time.Now()
			delay = r.minPollInterval
			if rest := r.minPollInterval - time.Since(polled); rest > 0 {
				select {
				case <-r.ctx.Done():
					return
				case <-time.After(rest):
				}
			}
		}
	}
}

func (r *walReader) poll() (advanced, eof bool, err error) {
	listed, err := r.storage.List(r.ctx, r.prefix)
	if err != nil {
		return false, false, err
	}
	if len(listed) == 0 {
		return false, false, nil
	}

	pending := make(map[int64]Entry, len(listed))
	ahead := false
	for _, entry := range listed {
		seq, ok := parseEntry(entry.Name)
		if !ok {
			continue
		}
		pending[seq] = entry
		if seq > r.seq {
			ahead = true
		}
	}

	if _, ok := pending[r.seq]; !ok && ahead {
		if r.holeSince.IsZero() {
			r.holeSince = time.Now()
		} else if time.Since(r.holeSince) >= r.holeTimeout {
			return false, false, errors.New("segment ", r.seq,
				" never arrived while later ones did, the peer lost it")
		}
	} else {
		r.holeSince = time.Time{}
	}

	type result struct {
		chunk []byte
		err   error
	}
	outstanding := make(map[int64]chan result)

	for {
		if entry, ok := pending[r.seq]; ok && strings.HasSuffix(entry.Name, errSuffix) {
			r.discard(r.prefix + "/" + entry.Name)
			return advanced, false, errors.New("the peer could not store segment ", r.seq)
		}
		if entry, ok := pending[r.seq]; ok && strings.HasSuffix(entry.Name, endSuffix) && len(outstanding) == 0 {
			r.discard(r.prefix + "/" + entry.Name)
			return advanced, true, nil
		}

		// keep the window of fetches full, so the next segments download
		// while the head one is handed over
		for i := int64(0); len(outstanding) < r.concurrency; i++ {
			seq := r.seq + i
			entry, ok := pending[seq]
			if !ok || !strings.HasSuffix(entry.Name, segSuffix) {
				break
			}
			if _, ok := outstanding[seq]; ok {
				continue
			}
			ch := make(chan result, 1)
			outstanding[seq] = ch
			if entry.Inline != nil {
				ch <- result{chunk: entry.Inline}
				continue
			}
			go func(name string) {
				chunk, err := r.storage.Get(r.ctx, r.prefix+"/"+name)
				ch <- result{chunk, err}
			}(entry.Name)
		}

		head, ok := outstanding[r.seq]
		if !ok {
			return advanced, false, nil
		}
		var res result
		select {
		case res = <-head:
		case <-r.ctx.Done():
			return advanced, true, nil
		}
		delete(outstanding, r.seq)
		if res.err != nil {
			if res.err == errNotFound {
				return advanced, false, nil
			}
			return advanced, false, res.err
		}
		select {
		case r.ch <- res.chunk:
		case <-r.ctx.Done():
			return advanced, true, nil
		}
		name := pending[r.seq].Name
		delete(pending, r.seq)
		r.seq++
		advanced = true
		r.discard(r.prefix + "/" + name)
	}
}

func (r *walReader) discard(name string) {
	select {
	case r.discards <- name:
	default:
	}
}

func (r *walReader) discardLoop() {
	var wg sync.WaitGroup
	defer wg.Wait()

	sem := make(chan struct{}, r.concurrency)
	for {
		select {
		case <-r.ctx.Done():
			return
		case name := <-r.discards:
			sem <- struct{}{}
			wg.Add(1)
			go func(name string) {
				defer wg.Done()
				defer func() { <-sem }()
				r.storage.Delete(r.ctx, name)
			}(name)
		}
	}
}

func (r *walReader) setErr(err error) {
	r.errMu.Lock()
	defer r.errMu.Unlock()
	if r.err == nil {
		r.err = err
	}
}

func (r *walReader) Err() error {
	r.errMu.Lock()
	defer r.errMu.Unlock()
	if r.err != nil {
		return r.err
	}
	return io.EOF
}
