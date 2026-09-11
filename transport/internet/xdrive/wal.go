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
	segSuffix = ".seg"
	endSuffix = ".end"
	errSuffix = ".err"
)

func segmentName(prefix string, seq int64) string {
	return fmt.Sprintf("%s/%09d%s", prefix, seq, segSuffix)
}

func endName(prefix string, seq int64) string {
	return fmt.Sprintf("%s/%09d%s", prefix, seq, endSuffix)
}

func errName(prefix string, seq int64) string {
	return fmt.Sprintf("%s/%09d%s", prefix, seq, errSuffix)
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
	params  params
	sem     chan struct{}
	wg      sync.WaitGroup

	mu       sync.Mutex
	buf      []byte
	seq      int64
	lastSize int
	waited   int
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
	for len(w.buf) >= w.params.segmentBytes {
		if err := w.flushLocked(); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (w *walWriter) flushLoop() {
	ticker := time.NewTicker(w.params.flushInterval)
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

	if grew && w.waited < maxCoalescedTicks {
		w.waited++
		return false
	}
	w.waited = 0
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
	if n > w.params.segmentBytes {
		n = w.params.segmentBytes
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
	w.waited = 0

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

	if err := w.storage.Put(w.ctx, segmentName(w.prefix, seq), chunk); err != nil {
		w.mu.Lock()
		if w.err == nil {
			w.err = errors.New("XDRIVE: failed to store segment").Base(err)
		}
		w.mu.Unlock()
		w.storage.Put(w.ctx, errName(w.prefix, seq), nil)
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
	return w.storage.Put(w.ctx, endName(w.prefix, seq), nil)
}

type walReader struct {
	ctx     context.Context
	storage Storage
	prefix  string
	params  params
	seq     int64

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

func (r *walReader) Wake() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *walReader) run() {
	defer close(r.ch)

	delay := r.params.minPollInterval
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
			delay = r.params.minPollInterval
		case time.Since(active) < r.params.eagerWindow:
			delay = r.params.minPollInterval
		default:
			delay *= 2
			if delay > r.params.maxPollInterval {
				delay = r.params.maxPollInterval
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
			delay = r.params.minPollInterval
			if rest := r.params.minPollInterval - time.Since(polled); rest > 0 {
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
		} else if time.Since(r.holeSince) >= r.params.holeTimeout {
			return false, false, errors.New("XDRIVE: segment ", r.seq,
				" never arrived while later ones did, the peer lost it")
		}
	} else {
		r.holeSince = time.Time{}
	}

	for {
		if entry, ok := pending[r.seq]; ok && strings.HasSuffix(entry.Name, errSuffix) {
			r.discard(r.prefix + "/" + entry.Name)
			return advanced, false, errors.New("XDRIVE: the peer could not store segment ", r.seq)
		}

		batch, done := r.nextBatch(pending)
		if done {
			return advanced, true, nil
		}
		if len(batch) == 0 {
			return advanced, false, nil
		}

		chunks, err := r.fetch(batch)
		if err != nil {
			if err == errNotFound {
				return advanced, false, nil
			}
			return advanced, false, err
		}

		for i, chunk := range chunks {
			select {
			case r.ch <- chunk:
			case <-r.ctx.Done():
				return advanced, true, nil
			}
			r.seq++
			advanced = true
			r.discard(r.prefix + "/" + batch[i].Name)
		}
	}
}

func (r *walReader) nextBatch(pending map[int64]Entry) (batch []Entry, done bool) {
	for i := 0; i < r.params.concurrency; i++ {
		entry, ok := pending[r.seq+int64(i)]
		if !ok {
			break
		}
		if !strings.HasSuffix(entry.Name, segSuffix) {
			if i == 0 && strings.HasSuffix(entry.Name, endSuffix) {
				r.discard(r.prefix + "/" + entry.Name)
				return nil, true
			}
			break
		}
		batch = append(batch, entry)
	}
	return batch, false
}

func (r *walReader) fetch(batch []Entry) ([][]byte, error) {
	chunks := make([][]byte, len(batch))
	failures := make([]error, len(batch))

	var wg sync.WaitGroup
	for i, entry := range batch {
		if entry.Inline != nil {
			chunks[i] = entry.Inline
			continue
		}
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			chunks[i], failures[i] = r.storage.Get(r.ctx, r.prefix+"/"+name)
		}(i, entry.Name)
	}
	wg.Wait()

	for i := range batch {
		if failures[i] != nil {
			return nil, failures[i]
		}
	}
	return chunks, nil
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

	sem := make(chan struct{}, r.params.concurrency)
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
