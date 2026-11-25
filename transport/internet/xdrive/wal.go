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
	sem       chan struct{}
	wg        sync.WaitGroup
	flushDone chan struct{}
	stop      chan struct{}
	failed    chan struct{}
	closeOnce sync.Once
	closeErr  error

	mu       sync.Mutex
	buf      []byte
	seq      int64
	lastSize int
	held     int
	closed   bool
	err      error
}

func newWALWriter(ctx context.Context, storage Storage, prefix string, p params) *walWriter {
	w := &walWriter{
		ctx:       ctx,
		storage:   storage,
		prefix:    prefix,
		params:    p,
		sem:       make(chan struct{}, p.concurrency),
		flushDone: make(chan struct{}),
		stop:      make(chan struct{}),
		failed:    make(chan struct{}),
	}
	go w.flushLoop()
	return w
}

func (w *walWriter) Write(p []byte) (int, error) {
	return w.writeUntil(p, nil, nil)
}

// writeUntil is Write that gives up with errWriteStopped, having returned the
// bytes it took into buf, once either channel is closed
func (w *walWriter) writeUntil(p []byte, deadline, closing <-chan struct{}) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.err != nil {
		return 0, w.err
	}
	if w.closed || w.ctx.Err() != nil {
		return 0, io.ErrClosedPipe
	}
	if isClosedChan(deadline) || isClosedChan(closing) {
		return 0, errWriteStopped
	}

	accepted := 0
	for len(p) > 0 {
		if w.err != nil {
			return accepted, w.err
		}
		if w.closed || w.ctx.Err() != nil {
			return accepted, io.ErrClosedPipe
		}
		if isClosedChan(deadline) || isClosedChan(closing) {
			return accepted, errWriteStopped
		}
		n := min(len(p), w.segmentBytes-len(w.buf))
		w.buf = append(w.buf, p[:n]...)
		accepted += n
		p = p[n:]
		for len(w.buf) >= w.segmentBytes {
			if err := w.flushLocked(deadline, closing); err != nil {
				return accepted, err
			}
		}
	}
	return accepted, nil
}

func (w *walWriter) flushLoop() {
	defer close(w.flushDone)
	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-w.stop:
			return
		case <-ticker.C:
			w.mu.Lock()
			if !w.closed && w.err == nil && len(w.buf) > 0 && w.readyToFlush() {
				w.flushLocked(nil, w.stop)
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

// flushLocked takes an upload permit before it cuts a segment, waiting without
// w.mu, so a store that falls behind holds Write back instead of piling up
// goroutines and chunks. Either stop channel, when closed, ends the wait with
// errWriteStopped
func (w *walWriter) flushLocked(deadline, closing <-chan struct{}) error {
	return w.flushLockedMode(deadline, closing, false)
}

func (w *walWriter) flushLockedMode(deadline, closing <-chan struct{}, draining bool) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if w.closed && !draining {
		return io.ErrClosedPipe
	}
	if len(w.buf) == 0 {
		return nil
	}
	if w.err != nil {
		return w.err
	}
	select {
	case <-deadline:
		return errWriteStopped
	case <-closing:
		return errWriteStopped
	default:
	}
	w.mu.Unlock()
	select {
	case w.sem <- struct{}{}:
	case <-w.failed:
		w.mu.Lock()
		return w.err
	case <-w.ctx.Done():
		w.mu.Lock()
		return w.ctx.Err()
	case <-deadline:
		w.mu.Lock()
		return errWriteStopped
	case <-closing:
		w.mu.Lock()
		return errWriteStopped
	}
	w.mu.Lock()
	if err := w.ctx.Err(); err != nil {
		<-w.sem
		return err
	}
	if w.closed && !draining {
		<-w.sem
		return io.ErrClosedPipe
	}
	if isClosedChan(deadline) || isClosedChan(closing) {
		<-w.sem
		return errWriteStopped
	}
	if w.err != nil || len(w.buf) == 0 {
		<-w.sem
		return w.err
	}

	n := len(w.buf)
	if n > w.segmentBytes {
		n = w.segmentBytes
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
	defer func() { <-w.sem }()
	if w.ctx.Err() != nil {
		return
	}

	err := w.storage.Put(w.ctx, objectName(w.prefix, seq, segSuffix), chunk)
	if err == nil && requiresWALCommit(w.storage) {
		err = w.storage.Put(w.ctx, objectName(w.prefix, seq, commitSuffix), encodeWALCommit(chunk))
	}
	if err != nil && w.ctx.Err() == nil {
		w.mu.Lock()
		if w.err == nil {
			w.err = errors.New("failed to store segment").Base(err)
			close(w.failed)
		}
		w.mu.Unlock()
		w.storage.Put(w.ctx, objectName(w.prefix, seq, errSuffix), nil)
	}
}

func (w *walWriter) Close() error {
	w.closeOnce.Do(func() {
		w.mu.Lock()
		w.closed = true
		close(w.stop)
		w.mu.Unlock()
		<-w.flushDone

		w.mu.Lock()
		var flushErr error
		for len(w.buf) > 0 && w.err == nil {
			if err := w.flushLockedMode(nil, nil, true); err != nil {
				flushErr = err
				break
			}
		}
		w.mu.Unlock()
		w.wg.Wait()

		w.mu.Lock()
		err, seq := w.err, w.seq
		w.mu.Unlock()
		switch {
		case err != nil:
			w.closeErr = err
		case w.ctx.Err() != nil:
			w.closeErr = w.ctx.Err()
		case flushErr != nil:
			w.closeErr = flushErr
		default:
			w.closeErr = w.storage.Put(w.ctx, objectName(w.prefix, seq, endSuffix), nil)
		}
	})
	return w.closeErr
}

type walReader struct {
	ctx     context.Context
	storage Storage
	prefix  string
	params
	seq int64

	ch        chan []byte
	discard   bool
	discards  chan string
	wake      chan struct{}
	holeSince time.Time

	errMu sync.Mutex
	err   error
	done  chan struct{}
	work  sync.WaitGroup
}

func newWALReader(ctx context.Context, storage Storage, prefix string, p params, discard bool) *walReader {
	r := &walReader{
		ctx:     ctx,
		storage: storage,
		prefix:  prefix,
		params:  p,
		ch:      make(chan []byte, p.concurrency),
		discard: discard,
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	if discard {
		r.discards = make(chan string, 4*p.concurrency)
		r.work.Add(1)
		go func() {
			defer r.work.Done()
			r.discardLoop()
		}()
	}
	go r.run()
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

func (r *walReader) wait() {
	<-r.done
	r.work.Wait()
}

func (r *walReader) run() {
	defer close(r.done)
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
		return false, false, r.pendingError(false)
	}

	pending := make(map[int64]Entry, len(listed))
	observedThrough := int64(-1)
	for _, entry := range listed {
		seq, ok := parseEntry(entry.Name)
		if !ok {
			if requiresWALCommit(r.storage) && strings.HasSuffix(entry.Name, commitSuffix) {
				seq, ok = parseEntry(strings.TrimSuffix(entry.Name, commitSuffix) + segSuffix)
				if ok {
					observedThrough = max(observedThrough, seq)
				}
			}
			continue
		}
		observedThrough = max(observedThrough, seq)
		if previous, exists := pending[seq]; exists && strings.HasSuffix(previous.Name, errSuffix) {
			continue
		}
		pending[seq] = entry
	}

	for {
		if _, ok := pending[r.seq]; !ok {
			if err := r.pendingError(observedThrough >= r.seq); err != nil {
				return advanced, false, err
			}
		}
		if entry, ok := pending[r.seq]; ok && strings.HasSuffix(entry.Name, errSuffix) {
			r.queueDiscard(r.prefix + "/" + entry.Name)
			return advanced, false, errors.New("the peer could not store segment ", r.seq)
		}

		batch, done := r.nextBatch(pending)
		if done {
			return advanced, true, nil
		}
		if len(batch) == 0 {
			return advanced, false, nil
		}

		chunks, err := r.fetch(batch)
		if err != nil && (err != errNotFound || len(chunks) == 0) {
			if err == errNotFound {
				return advanced, false, r.pendingError(true)
			}
			return advanced, false, err
		}

		for i, chunk := range chunks {
			select {
			case r.ch <- chunk:
			case <-r.ctx.Done():
				return advanced, true, nil
			}
			seq := r.seq
			r.seq++
			r.holeSince = time.Time{}
			advanced = true
			r.queueDiscard(r.prefix + "/" + batch[i].Name)
			if requiresWALCommit(r.storage) {
				r.queueDiscard(objectName(r.prefix, seq, commitSuffix))
			}
		}
		if err == errNotFound {
			return advanced, false, r.pendingError(true)
		}
	}
}

func (r *walReader) pendingError(observed bool) error {
	if r.holeSince.IsZero() {
		if observed {
			r.holeSince = time.Now()
		}
		return nil
	}
	if time.Since(r.holeSince) >= r.holeTimeout {
		return errors.New("segment ", r.seq, " did not complete before the stream progress timeout")
	}
	return nil
}

func (r *walReader) nextBatch(pending map[int64]Entry) (batch []Entry, done bool) {
	for i := 0; i < r.concurrency; i++ {
		entry, ok := pending[r.seq+int64(i)]
		if !ok {
			break
		}
		if !strings.HasSuffix(entry.Name, segSuffix) {
			if i == 0 && strings.HasSuffix(entry.Name, endSuffix) {
				r.queueDiscard(r.prefix + "/" + entry.Name)
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

	for _, err := range failures {
		if err != nil && err != errNotFound {
			return nil, err
		}
	}
	for _, chunk := range chunks {
		if len(chunk) > maxSegmentBytes {
			return nil, errors.New("segment exceeds the maximum size")
		}
	}
	commits := make([][]byte, len(batch))
	commitFailures := make([]error, len(batch))
	if requiresWALCommit(r.storage) {
		for i, entry := range batch {
			wg.Add(1)
			go func(i int, name string) {
				defer wg.Done()
				seq, _ := parseEntry(name)
				ctx := context.WithValue(r.ctx, maxBodyKey{}, int64(walCommitBytes))
				commits[i], commitFailures[i] = r.storage.Get(ctx, objectName(r.prefix, seq, commitSuffix))
			}(i, entry.Name)
		}
		wg.Wait()
		for _, err := range commitFailures {
			if err != nil && err != errNotFound {
				return nil, err
			}
		}
	}
	for i, err := range failures {
		if err != nil || len(chunks[i]) == 0 {
			return chunks[:i], errNotFound
		}
		if requiresWALCommit(r.storage) && (commitFailures[i] != nil || !validWALCommit(commits[i], chunks[i])) {
			return chunks[:i], errNotFound
		}
	}
	return chunks, nil
}

func (r *walReader) queueDiscard(name string) {
	if !r.discard {
		// Downlink segments stay until the server collects the idle session after sessionTTL.
		return
	}
	select {
	case r.discards <- name:
	default:
	}
}

func (r *walReader) discardLoop() {
	if !r.discard {
		return
	}
	var wg sync.WaitGroup
	defer wg.Wait()

	sem := make(chan struct{}, r.concurrency)
	for {
		select {
		case <-r.ctx.Done():
			return
		case name := <-r.discards:
			select {
			case sem <- struct{}{}:
			case <-r.ctx.Done():
				return
			}
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
