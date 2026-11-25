package xdrive

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

const (
	slotMagic        = "XDRVSL03"
	slotHeaderLen    = len(slotMagic) + 13
	slotInlineLimit  = 14 << 10
	slotInline       = 1
	slotEnd          = 3
	slotErr          = 4
	slotStream       = 5
	maxSlotIDLen     = 128
	slotStallTimeout = time.Minute

	// Every block has an 8-byte sequence tag, then up to slotTagBlock data bytes.
	// Each whole-block range independently rejects an older lap.
	slotBodyHeader = 8
	slotTagBlock   = 256 << 10
	// slotReadChunk is the unit a media body is delivered in while it downloads.
	slotReadChunk = 32 << 10
	// slotMaxFrame stays below Drive's 5 MB multipart upload limit.
	slotMaxFrame = 4 << 20
	// Routine credit takes 1-3 s; only longer waits indicate strain.
	slotStrainWait = 5 * time.Second
	// Small frames amortize service latency better with one progressive GET.
	slotProgressiveMax = 1 << 20
	slotReadAhead      = 24
	// A busy writer gathers until slotBusyGather, a full frame or input pause.
	slotBusyUploads = 4
	slotBusyGather  = 200 * time.Millisecond
)

func slotBlocks(size int) int { return (size + slotTagBlock - 1) / slotTagBlock }

// byteBudget bounds bytes in flight. A taker may exceed the limit when nothing
// else is in flight, so any single frame can always proceed.
type byteBudget struct {
	mu          sync.Mutex
	used, limit int
	free        chan struct{} // closed and replaced by every give
}

func newByteBudget(limit int) *byteBudget {
	return &byteBudget{limit: limit, free: make(chan struct{})}
}

// take waits until n bytes fit. It returns false if skip or done closes first.
func (b *byteBudget) take(n int, skip, done <-chan struct{}) bool {
	for {
		b.mu.Lock()
		if b.used == 0 || b.used+n <= b.limit {
			b.used += n
			b.mu.Unlock()
			return true
		}
		free := b.free
		b.mu.Unlock()
		select {
		case <-free:
		case <-skip:
			return false
		case <-done:
			return false
		}
	}
}

func (b *byteBudget) give(n int) {
	b.mu.Lock()
	b.used -= n
	close(b.free)
	b.free = make(chan struct{})
	b.mu.Unlock()
}

var errWriteStopped = errors.New("write stopped")

type slotStore interface {
	takeIDs(context.Context, int) ([]string, error)
	createSlot(context.Context, string, string, string, []byte) error
	setSlot(context.Context, string, string, []byte) error
	readDescription(context.Context, string) (string, error)
	readFrameStream(context.Context, string, slotFrame, func([]byte) error) error
}

// A slot description identifies its sequence and either carries the payload
// (inline) or the length of a media body stored in the same file.
type slotFrame struct {
	seq  int64
	mode byte
	size int
	data []byte
}

func (f slotFrame) encode() string {
	b := make([]byte, slotHeaderLen, slotHeaderLen+len(f.data))
	copy(b, slotMagic)
	binary.BigEndian.PutUint64(b[8:], uint64(f.seq))
	b[16] = f.mode
	binary.BigEndian.PutUint32(b[17:], uint32(f.size))
	b = append(b, f.data...)
	return base64.StdEncoding.EncodeToString(b)
}

func decodeSlot(description string) (slotFrame, bool) {
	b, err := base64.StdEncoding.DecodeString(description)
	if err != nil || len(b) < slotHeaderLen || string(b[:len(slotMagic)]) != slotMagic {
		return slotFrame{}, false
	}
	f := slotFrame{
		seq:  int64(binary.BigEndian.Uint64(b[8:])),
		mode: b[16],
		size: int(binary.BigEndian.Uint32(b[17:])),
	}
	if f.seq < 0 || f.size < 0 || f.size > maxSegmentBytes {
		return slotFrame{}, false
	}
	switch f.mode {
	case slotInline:
		f.data = b[slotHeaderLen:]
		if f.size == 0 || f.size > slotInlineLimit || len(f.data) != f.size {
			return slotFrame{}, false
		}
	case slotStream:
		if f.size == 0 || len(b) != slotHeaderLen {
			return slotFrame{}, false
		}
	case slotEnd, slotErr:
		if f.size != 0 || len(b) != slotHeaderLen {
			return slotFrame{}, false
		}
	default:
		return slotFrame{}, false
	}
	return f, true
}

// slotTable is the ring of one direction: the ids of its slots and of the
// watermark of its reader. name and lazy are local, not serialized.
type slotTable struct {
	Slots     []string `json:"s"`
	Watermark string   `json:"w"`
	name      string
	lazy      bool
}

// ring is what a client announces a session with, the tables are named from
// its side. Lazy rings create their slots on first write instead of up front.
type ring struct {
	Up    slotTable `json:"u"`
	Down  slotTable `json:"d"`
	First []byte    `json:"first,omitempty"`
	Lazy  bool      `json:"lazy,omitempty"`
}

// IDs are single opaque URL path components, never paths or special segments.
func validSlotIDs(seen map[string]bool, ids ...string) bool {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	for _, id := range ids {
		if id == "" || len(id) > maxSlotIDLen || strings.Trim(id, alphabet) != "" || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func decodeRing(b []byte) (ring, bool) {
	var r ring
	if json.Unmarshal(b, &r) != nil || len(r.First) > slotInlineLimit {
		return ring{}, false
	}
	seen := make(map[string]bool)
	for _, t := range []slotTable{r.Up, r.Down} {
		if len(t.Slots) == 0 || len(t.Slots) > maxConcurrency || !validSlotIDs(seen, t.Watermark) || !validSlotIDs(seen, t.Slots...) {
			return ring{}, false
		}
	}
	return r, true
}

// IDs are allocated in direction order: slots, watermark, slots, watermark.
func lazyRing(session string, depth int, ids []string) ring {
	table := func(name string, batch []string) slotTable {
		return slotTable{Slots: slices.Clone(batch[:depth]), Watermark: batch[depth], name: name, lazy: true}
	}
	return ring{Lazy: true, Up: table(uplinkPrefix(session), ids), Down: table(downlinkPrefix(session), ids[depth+1:])}
}

// Each object has one writer. Only its first publication in a lazy ring is a create.
func (t slotTable) publish(ctx context.Context, store slotStore, seq int64, mode byte, data []byte) error {
	idx := int(seq % int64(len(t.Slots)))
	f := slotFrame{seq: seq, mode: mode, size: len(data)}
	var body []byte
	if mode == slotStream {
		body = make([]byte, 0, len(data)+slotBodyHeader*slotBlocks(len(data)))
		for block := range slices.Chunk(data, slotTagBlock) {
			body = binary.BigEndian.AppendUint64(body, uint64(seq))
			body = append(body, block...)
		}
	} else if mode == slotInline {
		f.data = data
	}
	if t.lazy && seq < int64(len(t.Slots)) {
		return store.createSlot(ctx, t.Slots[idx], t.name+"/s"+strconv.Itoa(idx), f.encode(), body)
	}
	return store.setSlot(ctx, t.Slots[idx], f.encode(), body)
}

func isCooling(s slotStore) bool {
	c, ok := s.(interface{ cooling() bool })
	return ok && c.cooling()
}

// Outbound: run assigns sequence numbers and owns the coalescing buffer.
// Uploads may finish out of order. Each physical position has a completion fence.
type slotWriter struct {
	ctx   context.Context
	fail  context.CancelCauseFunc
	store slotStore
	table slotTable
	params
	input               chan []byte
	writeToken, permits chan struct{}
	stop, done          chan struct{}
	first               chan []byte
	closeOnce           sync.Once
	workers             sync.WaitGroup
	mu                  sync.Mutex
	progress            time.Time
	wmMu                sync.Mutex
	acked               int64
	checked             time.Time
	frame               int         // current media frame size, owned by run
	strained            atomic.Bool // set by a worker that waited long for credit
	flight              *byteBudget // bytes of unfinished uploads
}

func newSlotWriter(ctx context.Context, fail context.CancelCauseFunc, store slotStore, table slotTable, p params) *slotWriter {
	w := &slotWriter{
		ctx: ctx, fail: fail, store: store, table: table, params: p,
		input: make(chan []byte), writeToken: make(chan struct{}, 1),
		permits: make(chan struct{}, min(len(table.Slots), 32)),
		stop:    make(chan struct{}), done: make(chan struct{}),
		first: make(chan []byte, 1), acked: -1, progress: time.Now(),
		frame: min(p.segmentBytes, slotMaxFrame), flight: newByteBudget(p.flightBytes),
	}
	go w.run()
	return w
}

// Both directions observe the first fatal error, but END leaves the other half open.
func (w *slotWriter) Err() error { return context.Cause(w.ctx) }

func (w *slotWriter) stopped() error {
	if err := w.Err(); err != nil {
		return err
	}
	return io.ErrClosedPipe
}

func (w *slotWriter) Write(p []byte) (int, error) { return w.writeUntil(p, nil, nil) }

func (w *slotWriter) writeUntil(p []byte, deadline, closing <-chan struct{}) (int, error) {
	select {
	case w.writeToken <- struct{}{}:
		defer func() { <-w.writeToken }()
	case <-deadline:
		return 0, errWriteStopped
	case <-closing:
		return 0, errWriteStopped
	case <-w.ctx.Done():
		return 0, w.stopped()
	case <-w.stop:
		return 0, io.ErrClosedPipe
	}
	n := 0
	for len(p) > 0 {
		if isClosedChan(deadline) || isClosedChan(closing) {
			return n, errWriteStopped
		}
		if w.ctx.Err() != nil || isClosedChan(w.stop) {
			return n, w.stopped()
		}
		k := min(len(p), w.segmentBytes)
		select {
		case w.input <- bytes.Clone(p[:k]):
			n += k
			p = p[k:]
		case <-deadline:
			return n, errWriteStopped
		case <-closing:
			return n, errWriteStopped
		case <-w.ctx.Done():
			return n, w.stopped()
		case <-w.stop:
			return n, io.ErrClosedPipe
		}
	}
	return n, nil
}

func (w *slotWriter) markProgress() {
	w.mu.Lock()
	w.progress = time.Now()
	w.mu.Unlock()
}

func (w *slotWriter) closeProgress() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.progress
}

var errDriveWatermark = errors.New("invalid receiver watermark")

// Only one watermark GET per refresh interval, even when a wave wraps together.
func (w *slotWriter) credit(seq int64) (bool, error) {
	need := seq - int64(len(w.table.Slots))
	if need < 0 {
		return true, nil
	}
	w.wmMu.Lock()
	defer w.wmMu.Unlock()
	if w.acked >= seq {
		return false, errDriveWatermark
	}
	if w.acked >= need || time.Since(w.checked) < 100*time.Millisecond {
		return w.acked >= need, nil
	}
	ctx, cancel := context.WithTimeout(context.WithValue(w.ctx, headKey{}, true), 15*time.Second)
	defer cancel()
	d, err := w.store.readDescription(ctx, w.table.Watermark)
	w.checked = time.Now()
	if (err == errNotFound && w.table.lazy) || (err == nil && d == "") {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	n, err := strconv.ParseInt(d, 10, 64)
	if err != nil || n < 0 || n >= seq {
		return false, errDriveWatermark // this worker has not published seq yet
	}
	if n > w.acked {
		w.acked = n
		w.markProgress()
		errors.LogDebug(w.ctx, "xdrive credit seq ", seq, " ack ", n)
	}
	return w.acked >= need, nil
}

func (w *slotWriter) publish(seq int64, previous <-chan struct{}, mode byte, chunk []byte) error {
	if previous != nil {
		select {
		case <-previous:
		case <-w.ctx.Done():
			return w.stopped()
		}
	}
	since := time.Now()
	for {
		ok, err := w.credit(seq)
		if isAuthError(err) || err == errNotFound || err == errDriveScope || err == errDriveWatermark {
			return err
		}
		if ok {
			break
		}
		if time.Since(since) > slotStrainWait {
			w.strained.Store(true)
		}
		if time.Since(since) > slotStallTimeout && time.Since(w.closeProgress()) > slotStallTimeout {
			return errors.New("timed out waiting for receiver watermark").Base(err)
		}
		if err := sleepContext(w.ctx, 30*time.Millisecond); err != nil {
			return err
		}
	}
	if err := w.ctx.Err(); err != nil {
		return err
	}
	credited := time.Now()
	if err := w.table.publish(w.ctx, w.store, seq, mode, chunk); err != nil {
		// A lost reply is not a refusal: never overwrite possibly committed data.
		if _, refused := err.(refusedPayload); refused && w.ctx.Err() == nil {
			ctx, cancel := context.WithTimeout(w.ctx, 2*time.Second)
			_ = w.table.publish(ctx, w.store, seq, slotErr, nil)
			cancel()
		}
		return err
	}
	if mode == slotStream {
		errors.LogDebug(w.ctx, "xdrive upload seq ", seq, " bytes ", len(chunk), " credit ", credited.Sub(since), " put ", time.Since(credited))
	}
	w.markProgress()
	return nil
}

func (w *slotWriter) run() {
	defer close(w.done)
	defer w.workers.Wait()
	var seq int64
	var mediaAt time.Time // keep bulk bursts out of inline waves between uploads
	fences := make([]chan struct{}, len(w.table.Slots))
	launch := func(chunk []byte) bool {
		select {
		case w.permits <- struct{}{}:
		case <-w.ctx.Done():
			return false
		}
		if !w.flight.take(len(chunk), nil, w.ctx.Done()) {
			<-w.permits
			return false
		}
		n := seq
		seq++
		i := n % int64(len(fences))
		prev, done := fences[i], make(chan struct{})
		fences[i] = done
		mode := byte(slotStream)
		if len(chunk) <= slotInlineLimit {
			mode = slotInline
			if n == 0 {
				w.first <- chunk
			}
		} else {
			mediaAt = time.Now()
		}
		w.workers.Go(func() {
			defer close(done)
			defer func() { <-w.permits }()
			defer w.flight.give(len(chunk))
			if err := w.publish(n, prev, mode, chunk); err != nil {
				w.fail(err)
			}
		})
		return true
	}
	var buf []byte
	var bufAt, lastIn time.Time // arrival of the oldest and the newest buffered byte
	timer := time.NewTimer(w.flushInterval)
	timer.Stop()
	defer timer.Stop()
	base := w.frame
	flush := func() bool {
		timer.Stop()
		frame, full := w.frame, len(buf) >= w.frame
		// Credit strain reduces bytes; request quotas need larger frames, not smaller.
		strained, cooling := w.strained.Swap(false), isCooling(w.store)
		if strained && !cooling {
			w.frame = max(base, w.frame/2)
		} else if full && !cooling {
			w.frame = min(2*w.frame, slotMaxFrame)
		}
		if w.frame != frame {
			errors.LogDebug(w.ctx, "xdrive frame size ", frame, " -> ", w.frame, " strained=", strained, " cooling=", cooling, " uploads=", len(w.permits))
		}
		// Inline waves help idle latency; bulk traffic must not waste ring positions.
		unit := min(frame, slotInlineLimit)
		wave := min(24, cap(w.permits)-len(w.permits))
		inline := min(len(buf), wave*unit)
		if cooling || len(w.permits) >= slotBusyUploads || time.Since(mediaAt) < w.eagerWindow || len(buf) > wave*unit && (wave < 24 || len(buf) > frame) {
			inline = 0
		}
		for len(buf) > 0 {
			n := min(len(buf), frame)
			if inline > 0 {
				n = min(inline, unit)
				inline -= n
			}
			if !launch(buf[:n:n]) {
				return false
			}
			buf = buf[n:]
		}
		buf = nil // the upload workers own their slices
		return true
	}
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-w.stop:
			if !flush() {
				return
			}
			w.workers.Wait()
			if w.ctx.Err() == nil {
				if err := w.publish(seq, fences[seq%int64(len(fences))], slotEnd, nil); err != nil {
					w.fail(err)
				}
			}
			return
		case b := <-w.input:
			lastIn = time.Now()
			if len(buf) == 0 {
				buf, bufAt = b, time.Now()
				d := w.flushInterval
				if len(w.permits) == 0 && len(b) <= slotInlineLimit && !isCooling(w.store) {
					d = min(d, 2*time.Millisecond)
				}
				timer.Reset(d)
			} else {
				buf = append(buf, b...)
			}
			if len(buf) >= w.frame && !flush() {
				return
			}
		case <-timer.C:
			// Streaming: keep gathering toward a full frame while input keeps
			// coming, but send a burst once input pauses for flushInterval.
			quiet := w.flushInterval - time.Since(lastIn)
			if wait := slotBusyGather - time.Since(bufAt); len(w.permits) >= slotBusyUploads && wait > 0 && quiet > 0 {
				timer.Reset(min(wait, quiet))
				continue
			}
			if !flush() {
				return
			}
		}
	}
}

func (w *slotWriter) Close() error {
	w.closeOnce.Do(func() { close(w.stop) })
	w.wait() // Conn.Close owns the watchdog for the entire shutdown.
	return w.Err()
}

func (w *slotWriter) wait() { <-w.done }

func waitCloseProgress(done <-chan struct{}, progress func() time.Time) error {
	for {
		remaining := slotStallTimeout - time.Since(progress())
		if remaining <= 0 {
			select {
			case <-done:
				return nil
			default:
				return context.DeadlineExceeded
			}
		}
		select {
		case <-done:
			return nil
		case <-time.After(remaining):
		}
	}
}

// Inbound: workers discover known IDs concurrently. Only run delivers bytes and moves
// head. Lookahead media retains at most flightBytes, plus the ordered head.
type slotReader struct {
	ctx     context.Context
	setErr  context.CancelCauseFunc
	discard <-chan struct{}
	store   slotStore
	table   slotTable
	params
	ch                       chan []byte
	wake, ack                chan struct{}
	media                    *byteBudget // bodies downloaded ahead of the head
	head, frontier, activeAt atomic.Int64
	drainCredit              atomic.Pointer[time.Time] // last credit returned during Close
	probing                  atomic.Bool
	wg                       sync.WaitGroup
}

type readSlot struct {
	seq         int64
	prior       <-chan struct{} // previous frame's ready: ordered body admission
	head, ready chan struct{}
	data        chan []byte // published by ready; closed after the last verified block
	end         bool
	err         error // published by closing ready (no data) or data
}

func newSlotReader(ctx context.Context, fail context.CancelCauseFunc, store slotStore, table slotTable, p params, first []byte, discard <-chan struct{}) *slotReader {
	r := &slotReader{
		ctx: ctx, setErr: fail, discard: discard, store: store, table: table, params: p,
		ch: make(chan []byte, 2), wake: make(chan struct{}, 1),
		ack: make(chan struct{}, 1), media: newByteBudget(p.flightBytes),
	}
	r.frontier.Store(-1)
	r.Wake()
	if len(first) != 0 {
		r.ch <- first
		r.head.Store(1)
		r.ack <- struct{}{}
	}
	readDone := make(chan struct{})
	r.wg.Go(func() {
		defer close(readDone)
		r.run()
	})
	r.wg.Go(func() { r.ackLoop(readDone) })
	return r
}

func (r *slotReader) chunks() <-chan []byte { return r.ch }
func (r *slotReader) wait()                 { r.wg.Wait() }

func (r *slotReader) Wake() {
	r.activeAt.Store(time.Now().UnixNano())
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *slotReader) Err() error {
	if err := context.Cause(r.ctx); err != nil {
		return err
	}
	return io.EOF
}

func (r *slotReader) observe(n int64) {
	for old := r.frontier.Load(); old < n && !r.frontier.CompareAndSwap(old, n); old = r.frontier.Load() {
	}
}

func (r *slotReader) lookup(ctx context.Context, job *readSlot) (slotFrame, error) {
	depth := int64(len(r.table.Slots))
	id := r.table.Slots[job.seq%depth]
	probeAt, offset := time.Now().Add(slotStallTimeout), int64(1)
	var unhealthy time.Time
	for {
		head := job.seq == r.head.Load()
		active := time.Since(time.Unix(0, r.activeAt.Load())) < r.eagerWindow
		// Empty distant slots must not spend the quota of useful media and ACKs.
		if head || active && job.seq <= max(r.frontier.Load(), r.head.Load())+4 {
			readCtx := ctx
			if head {
				readCtx = context.WithValue(ctx, headKey{}, true)
			}
			d, err := r.store.readDescription(readCtx, id)
			f, ok := decodeSlot(d)
			invalid := d != "" && !ok
			if err == nil && f.seq > job.seq {
				return slotFrame{}, errors.New("Drive slot ", job.seq, " was overwritten by sequence ", f.seq)
			}
			if err == nil && f.mode != 0 && f.seq == job.seq {
				r.activeAt.Store(time.Now().UnixNano())
				r.observe(f.seq)
				return f, nil
			}
			if err == errDriveScope || isAuthError(err) {
				return slotFrame{}, err
			}
			// A lazy missing head may be idle; probe other descriptions for a gap.
			if head && depth > 1 && time.Now().After(probeAt) && r.frontier.Load() <= job.seq && !isCooling(r.store) && r.probing.CompareAndSwap(false, true) {
				idx := (job.seq + offset) % depth
				offset, probeAt = offset%(depth-1)+1, time.Now().Add(slotStallTimeout/12)
				r.wg.Go(func() {
					defer r.probing.Store(false)
					probe, cancel := context.WithTimeout(ctx, slotStallTimeout)
					defer cancel()
					d, err := r.store.readDescription(probe, r.table.Slots[idx])
					if f, ok := decodeSlot(d); err == nil && ok && f.seq > job.seq && f.seq%depth == idx {
						r.observe(f.seq)
						r.Wake()
					}
				})
			}
			missing := err == errNotFound && (!r.table.lazy || job.seq >= int64(len(r.table.Slots)))
			if head && (missing || (err != nil && err != errNotFound) || invalid || r.frontier.Load() > job.seq) {
				if unhealthy.IsZero() {
					unhealthy = time.Now()
				} else if time.Since(unhealthy) >= slotStallTimeout {
					return slotFrame{}, errors.New("Drive slot ", job.seq, " did not become readable").Base(err)
				}
			} else {
				unhealthy = time.Time{}
			}
		}
		wake, delay := job.head, 40*time.Millisecond
		if head {
			wake, delay = r.wake, 25*time.Millisecond
		}
		if !active {
			delay = r.maxPollInterval
		}
		select {
		case <-ctx.Done():
			return slotFrame{}, ctx.Err()
		case <-wake:
		case <-time.After(delay):
		}
	}
}

func (r *slotReader) fetch(ctx context.Context, j *readSlot) {
	start := time.Now()
	f, err := r.lookup(ctx, j)
	found := time.Now()
	// Discover concurrently, but reserve body bytes in sequence order.
	if j.prior != nil {
		select {
		case <-j.prior:
		case <-j.head:
		case <-ctx.Done():
			j.err = ctx.Err()
			close(j.ready)
			return
		}
	}
	if err != nil || f.mode == slotErr || f.mode == slotEnd {
		j.err, j.end = err, f.mode == slotEnd
		if f.mode == slotErr {
			j.err = errors.New("peer could not store segment ", j.seq)
		}
		close(j.ready)
		return
	}
	if f.mode == slotInline {
		j.data = make(chan []byte, 1)
		j.data <- f.data
		close(j.data)
		close(j.ready)
		return
	}
	// The ordered head has its own allowance; only successors use look-ahead bytes.
	ctx = context.WithValue(ctx, mediaHeadKey{}, (<-chan struct{})(j.head))
	if j.seq != r.head.Load() {
		reserved := r.media.take(f.size, j.head, ctx.Done())
		if !reserved && ctx.Err() != nil {
			j.err = ctx.Err()
			close(j.ready)
			return
		}
		if reserved {
			r.wg.Go(func() {
				select {
				case <-j.head:
				case <-ctx.Done():
				}
				r.media.give(f.size)
			})
		}
	}
	j.data = make(chan []byte, f.size/slotReadChunk+slotBlocks(f.size)+1) // pieces never cross a block
	close(j.ready)
	got := time.Now()
	j.err = r.store.readFrameStream(ctx, r.table.Slots[j.seq%int64(len(r.table.Slots))], f, func(b []byte) error {
		select {
		case j.data <- b:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	close(j.data)
	errors.LogDebug(ctx, "xdrive read seq ", j.seq, " bytes ", f.size, " find ", found.Sub(start), " budget ", got.Sub(found), " body ", time.Since(got), " err ", j.err)
}

func (r *slotReader) run() {
	defer close(r.ch)
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	jobs := make(map[int64]*readSlot)
	next := r.head.Load()
	for ctx.Err() == nil {
		head := r.head.Load()
		window := min(slotReadAhead, len(r.table.Slots))
		if head == 0 {
			window = 1
		}
		for next < head+int64(window) {
			j := &readSlot{seq: next, head: make(chan struct{}), ready: make(chan struct{})}
			if prior := jobs[next-1]; prior != nil {
				j.prior = prior.ready
			}
			jobs[next] = j
			r.wg.Go(func() { r.fetch(ctx, j) })
			next++
		}
		j := jobs[head]
		close(j.head)
		select {
		case <-j.ready:
		case <-ctx.Done():
			return
		}
		if j.data != nil {
			for b := range j.data {
				select {
				case r.ch <- b:
				case <-r.discard: // Close abandons input but must keep returning verified ring credit.
				case <-ctx.Done():
					return
				}
				r.activeAt.Store(time.Now().UnixNano()) // ordered input keeps look-ahead eager
			}
		}
		delete(jobs, head)
		if j.err != nil {
			if ctx.Err() == nil {
				r.setErr(j.err)
			}
			return
		}
		if j.end {
			return
		}
		r.head.Store(head + 1)
		select {
		case r.ack <- struct{}{}:
		default:
		}
	}
}

// This goroutine is the only watermark writer. END triggers one last snapshot
// after the ordered reader has stopped, including credit below the batch size.
func (r *slotReader) ackLoop(readDone <-chan struct{}) {
	ctx := context.WithValue(r.ctx, headKey{}, true)
	t := time.NewTicker(1500 * time.Millisecond)
	defer t.Stop()
	acked := int64(-1)
	batch := max(int64(1), int64(len(r.table.Slots))/6)
	for {
		final := false
		select {
		case <-ctx.Done():
			return
		case <-readDone:
			final = true
		case <-r.ack:
			if r.head.Load()-1-acked < batch {
				continue
			}
		case <-t.C:
		}
		if ctx.Err() != nil {
			return
		}
		if n := r.head.Load() - 1; n > acked {
			d := strconv.FormatInt(n, 10)
			started := time.Now()
			var err error
			if r.table.lazy && acked < 0 {
				err = r.store.createSlot(ctx, r.table.Watermark, r.table.name+"/w", d, nil)
			} else {
				err = r.store.setSlot(ctx, r.table.Watermark, d, nil)
			}
			if err != nil {
				r.setErr(errors.New("cannot publish Drive watermark").Base(err))
				return
			}
			acked = n
			errors.LogDebug(ctx, "xdrive watermark seq ", n, " put ", time.Since(started))
			if isClosedChan(r.discard) {
				now := time.Now()
				r.drainCredit.Store(&now)
			}
		}
		if final {
			return
		}
	}
}
