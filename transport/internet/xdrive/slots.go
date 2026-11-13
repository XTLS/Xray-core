package xdrive

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// A session on a slotStore is carried in a ring of slots for each direction,
// objects that both peers know by id: segment n is written to slot n % depth
// and read from it, with nothing to list and no index to wait for. The reader
// of a direction keeps how far it has read in a watermark, and the writer
// reuses a slot only once that says what was in it before was taken

const (
	slotMagic     = "XDRVSL01"
	slotHeaderLen = len(slotMagic) + 8 + 1 + 4 + 4
	// slotInlineLimit is how large a segment is at most to go in the description
	// of its slot, which takes one request less than a body
	slotInlineLimit = 14 << 10
	// inlineRampSegments segments of one size in a row double it, from
	// slotInlineLimit up to segmentBytes
	inlineRampSegments = 8

	slotInline = 1
	slotMedia  = 2
	slotEnd    = 3
	slotErr    = 4

	// maxSlotIDLen bounds any slot or watermark id accepted from a peer.
	maxSlotIDLen = 128
)

var (
	// the head is asked for between slotHuntFloor and slotHuntCeiling, a segment
	// behind it at about the pace that segments come
	slotHuntFloor   = 10 * time.Millisecond
	slotHuntCeiling = 25 * time.Millisecond
	slotTailMin     = 150 * time.Millisecond
	slotTailMax     = 800 * time.Millisecond
	slotFetchAhead  = 12

	slotAckRetry     = 30 * time.Millisecond
	slotWatermarkTTL = 100 * time.Millisecond
	slotStallTimeout = 60 * time.Second
	slotCloseGrace   = 10 * time.Second
	slotGoneTimeout  = 60 * time.Second
	slotBodyHedge    = 2 * time.Second

	slotReadAhead      int64 = 3
	slotReadAheadPoll        = 40 * time.Millisecond
	slotReadAheadBurst       = 500 * time.Millisecond
)

var slotWriteInflight = 12

// slotStore is a storage of objects that are written and read again by id,
// each with a description and a body
type slotStore interface {
	makeSlot(ctx context.Context, name string) (string, error)
	// setSlot sets the description of a slot and, unless body is nil, its body
	setSlot(ctx context.Context, id, description string, body []byte) error
	readDescription(ctx context.Context, id string) (string, error)
	readBody(ctx context.Context, id string) ([]byte, error)
}

// throttleStore is the optional part of a slotStore that reports how often
// Drive throttled or timed out its requests; only driveStorage implements it
type throttleStore interface {
	throttled() int64
}

// slotFrame is what the description of a slot says: which segment it holds,
// and either the segment itself or the size and checksum of the body that does
type slotFrame struct {
	seq  int64
	mode byte
	size int
	crc  uint32
	data []byte
}

func newSlotFrame(seq int64, mode byte, data []byte) slotFrame {
	f := slotFrame{seq: seq, mode: mode, size: len(data), crc: crc32.ChecksumIEEE(data)}
	if mode == slotInline {
		f.data = data
	}
	return f
}

func (f slotFrame) encode() string {
	b := make([]byte, slotHeaderLen, slotHeaderLen+len(f.data))
	copy(b, slotMagic)
	binary.BigEndian.PutUint64(b[8:], uint64(f.seq))
	b[16] = f.mode
	binary.BigEndian.PutUint32(b[17:], uint32(f.size))
	binary.BigEndian.PutUint32(b[21:], f.crc)
	return base64.StdEncoding.EncodeToString(append(b, f.data...))
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
		crc:  binary.BigEndian.Uint32(b[21:]),
	}
	if f.mode == slotInline {
		f.data = b[slotHeaderLen:]
		if !f.holds(f.data) {
			return slotFrame{}, false
		}
	}
	return f, true
}

// holds reports whether body is the one that f is about, which a body read
// right after its description need not be yet
func (f slotFrame) holds(body []byte) bool {
	return len(body) == f.size && crc32.ChecksumIEEE(body) == f.crc
}

// slotTable is the ring of one direction: the ids of its slots and of the
// watermark of its reader
type slotTable struct {
	Slots     []string `json:"s"`
	Watermark string   `json:"w"`
}

// ring is what a client announces a session with, the tables are named from
// its side
type ring struct {
	Up    slotTable `json:"u"`
	Down  slotTable `json:"d"`
	First []byte    `json:"first,omitempty"`
}

func decodeRing(b []byte) (ring, bool) {
	var r ring
	if json.Unmarshal(b, &r) != nil || len(r.Up.Slots) == 0 || len(r.Down.Slots) == 0 ||
		r.Up.Watermark == "" || r.Down.Watermark == "" {
		return ring{}, false
	}
	if len(r.Up.Slots) > maxConcurrency || len(r.Down.Slots) > maxConcurrency {
		return ring{}, false
	}
	for _, t := range []slotTable{r.Up, r.Down} {
		if len(t.Watermark) > maxSlotIDLen {
			return ring{}, false
		}
		for _, id := range t.Slots {
			if len(id) == 0 || len(id) > maxSlotIDLen {
				return ring{}, false
			}
		}
	}
	return r, true
}

// makeRing makes the slots and watermarks of a session, all at once
func makeRing(ctx context.Context, store slotStore, session string, p params) (ring, error) {
	depth := max(p.concurrency, 2)
	r := ring{
		Up:   slotTable{Slots: make([]string, depth)},
		Down: slotTable{Slots: make([]string, depth)},
	}
	var (
		wg      sync.WaitGroup
		errOnce sync.Once
		err     error
	)
	create := func(id *string, name string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var e error
			if *id, e = store.makeSlot(ctx, name); e != nil {
				errOnce.Do(func() { err = e })
			}
		}()
	}
	for _, t := range []struct {
		table  *slotTable
		prefix string
	}{{&r.Up, uplinkPrefix(session)}, {&r.Down, downlinkPrefix(session)}} {
		for i := range t.table.Slots {
			create(&t.table.Slots[i], t.prefix+"/s"+strconv.Itoa(i))
		}
		create(&t.table.Watermark, t.prefix+"/w")
	}
	wg.Wait()
	return r, err
}

func readWatermark(ctx context.Context, store slotStore, id string) (int64, error) {
	d, err := store.readDescription(context.WithValue(ctx, laneKey{}, true), id)
	if err != nil || d == "" {
		return -1, err
	}
	return strconv.ParseInt(d, 10, 64)
}

type slotWriter struct {
	ctx   context.Context
	store slotStore
	table slotTable
	params
	// slots bounds the number of segments on their way.
	slots chan struct{}
	wg    sync.WaitGroup

	mu       sync.Mutex
	uploads  []<-chan struct{} // Last upload completion per physical slot, guarded by mu.
	buf      []byte
	seq      int64
	size     int
	full     int
	lastSize int
	held     int
	closed   bool
	err      error
	first    chan []byte

	// ackMu is held while the watermark is read, which other uploads wait for
	ackMu    sync.Mutex
	acked    int64
	ackedAt  time.Time
	progress time.Time
}

func newSlotWriter(ctx context.Context, store slotStore, table slotTable, p params) *slotWriter {
	w := &slotWriter{
		ctx:      ctx,
		store:    store,
		table:    table,
		params:   p,
		slots:    make(chan struct{}, min(len(table.Slots), slotWriteInflight)),
		uploads:  make([]<-chan struct{}, len(table.Slots)),
		size:     min(slotInlineLimit, p.segmentBytes),
		acked:    -1,
		progress: time.Now(),
	}
	go w.flushLoop()
	return w
}

func (w *slotWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.err != nil {
		return 0, w.err
	}
	if w.closed || w.ctx.Err() != nil {
		return 0, io.ErrClosedPipe
	}

	w.buf = append(w.buf, p...)
	for len(w.buf) >= w.size {
		if err := w.flushLocked(); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (w *slotWriter) flushLoop() {
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

func (w *slotWriter) readyToFlush() bool {
	grew := len(w.buf) > w.lastSize
	w.lastSize = len(w.buf)

	if len(w.slots) > 0 && w.held < maxCoalescedTicks && len(w.buf) < w.size/2 {
		w.held++
		return false
	}
	if grew && w.held < maxCoalescedTicks {
		w.held++
		return false
	}
	w.held = 0
	return true
}

// flushLocked sends a segment off buf once a slot is free, which it waits for
// without w.mu, so that a reader that falls behind holds Write back. w.mu is
// held
func (w *slotWriter) flushLocked() error {
	w.mu.Unlock()
	select {
	case w.slots <- struct{}{}:
	case <-w.ctx.Done():
		w.mu.Lock()
		return w.ctx.Err()
	}
	w.mu.Lock()
	if err := w.ctx.Err(); err != nil {
		<-w.slots
		return err
	}
	if w.err != nil || len(w.buf) == 0 {
		<-w.slots
		return w.err
	}

	if w.size < w.segmentBytes && len(w.buf) >= w.size && len(w.slots)*4 > cap(w.slots)*3 {
		w.size = w.segmentBytes
		w.full = 0
	}

	n := min(len(w.buf), w.size)
	if len(w.buf) > 4*slotInlineLimit {
		// a burst goes at the full size at once
		n = min(len(w.buf), w.segmentBytes)
	}
	if n > slotInlineLimit && len(w.buf) <= 2*cap(w.slots)*slotInlineLimit {
		n = slotInlineLimit
	}
	if n == w.size && w.size < w.segmentBytes {
		if w.full++; w.full == inlineRampSegments {
			w.full = 0
			w.size = min(2*w.size, w.segmentBytes)
		}
	}

	chunk := bytes.Clone(w.buf[:n])
	w.buf = append(w.buf[:0], w.buf[n:]...)
	seq := w.seq
	w.seq++
	slot := seq % int64(len(w.table.Slots))
	previous := w.uploads[slot]
	done := make(chan struct{})
	w.uploads[slot] = done
	if seq == 0 && w.first != nil {
		select {
		case w.first <- chunk:
		default:
		}
	}
	w.lastSize = len(w.buf)
	w.held = 0

	w.wg.Add(1)
	go w.upload(seq, chunk, previous, done)
	return nil
}

func (w *slotWriter) slotID(seq int64) string {
	return w.table.Slots[seq%int64(len(w.table.Slots))]
}

func (w *slotWriter) upload(seq int64, chunk []byte, previous <-chan struct{}, done chan<- struct{}) {
	defer w.wg.Done()
	defer func() { <-w.slots }()
	defer close(done)
	if previous != nil {
		select {
		case <-previous:
		case <-w.ctx.Done():
		}
	}
	if err := w.ctx.Err(); err != nil {
		w.fail(errors.New("failed to store segment ", seq).Base(err))
		return
	}

	mode := byte(slotMedia)
	if len(chunk) <= slotInlineLimit {
		mode = slotInline
	}
	began := time.Now()
	if err := w.await(seq); err != nil {
		w.fail(errors.New("failed to store segment ", seq).Base(err))
		return
	}
	awaited := time.Since(began)
	putAt := time.Now()
	if err := w.write(seq, mode, chunk); err != nil {
		w.fail(errors.New("failed to store segment ", seq).Base(err))
		// the slot is free, the reader learns there what happened
		w.write(seq, slotErr, nil)
		return
	}
	errors.LogDebug(w.ctx, "xdrive write ", slotTag(w.table.Watermark), " seq=", seq, " bytes=", len(chunk),
		" mode=", mode, " await=", awaited, " put=", time.Since(putAt))
}

func (w *slotWriter) write(seq int64, mode byte, data []byte) error {
	f := newSlotFrame(seq, mode, data)
	var body []byte
	if mode == slotMedia {
		body = data
	}
	return w.store.setSlot(w.ctx, w.slotID(seq), f.encode(), body)
}

// drained reports whether the reader took what the slot of seq held a lap
// before. The watermark is read again only after slotWatermarkTTL, as one
// that is old costs a wait but never what is in a slot
func (w *slotWriter) drained(seq int64) (bool, error) {
	w.ackMu.Lock()
	defer w.ackMu.Unlock()

	before := seq - int64(len(w.table.Slots))
	if w.acked >= before {
		return true, nil
	}
	if time.Since(w.ackedAt) < slotWatermarkTTL {
		return false, nil
	}
	acked, err := readWatermark(w.ctx, w.store, w.table.Watermark)
	if err != nil {
		return false, err
	}
	w.ackedAt = time.Now()
	if acked > w.acked {
		w.acked, w.progress = acked, w.ackedAt
	}
	return w.acked >= before, nil
}

// await waits for drained, for slotStallTimeout at most, or slotCloseGrace
// without progress once the writer is closed
func (w *slotWriter) await(seq int64) error {
	start := time.Now()
	wait := slotAckRetry
	for {
		ok, err := w.drained(seq)
		if ok {
			return nil
		}
		w.mu.Lock()
		closed := w.closed
		w.mu.Unlock()
		w.ackMu.Lock()
		still := time.Since(w.progress)
		w.ackMu.Unlock()
		if min(time.Since(start), still) > slotStallTimeout || closed && still > slotCloseGrace {
			return errors.New("the reader took nothing from slot ", w.slotID(seq), " for ", still).Base(err)
		}

		if err != nil {
			wait = min(2*wait, 2*time.Second)
		} else {
			wait = slotAckRetry
		}
		select {
		case <-w.ctx.Done():
			return w.ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (w *slotWriter) fail(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err == nil {
		w.err = err
	}
}

func (w *slotWriter) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	for len(w.buf) > 0 && w.err == nil {
		if err := w.flushLocked(); err != nil {
			w.mu.Unlock()
			return err
		}
	}
	seq := w.seq
	w.mu.Unlock()

	w.ackMu.Lock()
	w.progress = time.Now()
	w.ackMu.Unlock()

	w.wg.Wait()

	w.mu.Lock()
	err := w.err
	w.mu.Unlock()
	if err != nil {
		return err
	}
	if err := w.await(seq); err != nil {
		return err
	}
	return w.write(seq, slotEnd, nil)
}

type slotReader struct {
	ctx   context.Context
	store slotStore
	table slotTable
	params

	ch   chan []byte
	wake chan struct{}
	acks chan struct{}
	grow chan struct{}

	mu      sync.Mutex
	head    int64
	started bool
	// hitAt is when a segment last came and gap the time between them, activeAt
	// when a segment came, was seen coming or Wake. Nothing for the eager window
	// is idle, and active is closed when that ends
	hitAt        time.Time
	gap          time.Duration
	activeAt     time.Time
	active       chan struct{}
	frontier     int64
	err          error
	stop         context.CancelFunc
	reads        atomic.Int64
	tailMin      time.Duration
	tailMax      time.Duration
	stallTimeout time.Duration
	bodyRate     float64
}

func newSlotReader(ctx context.Context, store slotStore, table slotTable, p params, first []byte) *slotReader {
	head := int64(0)
	if len(first) > 0 {
		head = 1
	}
	runCtx, stop := context.WithCancel(ctx)
	r := &slotReader{
		ctx:          runCtx,
		stop:         stop,
		store:        store,
		table:        table,
		params:       p,
		head:         head,
		started:      len(first) > 0,
		ch:           make(chan []byte, max(p.concurrency, 1)),
		wake:         make(chan struct{}, 1),
		acks:         make(chan struct{}, 1),
		grow:         make(chan struct{}, 1),
		hitAt:        time.Now(),
		activeAt:     time.Now(),
		active:       make(chan struct{}),
		tailMin:      slotTailMin,
		tailMax:      slotTailMax,
		stallTimeout: slotStallTimeout,
	}
	if len(first) > 0 {
		r.ch <- first
		select {
		case r.acks <- struct{}{}:
		default:
		}
	}
	go r.run()
	go r.ackLoop()
	return r
}

func (r *slotReader) chunks() <-chan []byte {
	return r.ch
}

// Wake has the head asked for now, as an answer is likely to come
func (r *slotReader) Wake() {
	r.mu.Lock()
	r.touch()
	r.mu.Unlock()
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *slotReader) slotID(seq int64) string {
	return r.table.Slots[seq%int64(len(r.table.Slots))]
}

type slotFetch struct {
	ready chan struct{}
	// promoted is closed when the segment becomes the head
	promoted chan struct{}
	near     chan struct{}
	body     []byte
	end      bool
	err      error
	born     time.Time
	readyAt  time.Time
}

func (f *slotFetch) enter() {
	select {
	case <-f.near:
	default:
		close(f.near)
	}
}

func (r *slotReader) run() {
	defer close(r.ch)
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()

	fetches := make(map[int64]*slotFetch)
	for {
		r.mu.Lock()
		head, started, frontier := r.head, r.started, r.frontier
		r.mu.Unlock()

		window := 1
		if started {
			window = min(max(int(frontier-head)+slotFetchAhead, slotFetchAhead), len(r.table.Slots))
		}
		for i := range window {
			seq := head + int64(i)
			if fetches[seq] == nil {
				fetches[seq] = &slotFetch{ready: make(chan struct{}), promoted: make(chan struct{}), near: make(chan struct{}), born: time.Now()}
				if int64(i) <= slotReadAhead {
					fetches[seq].enter()
				}
				go r.fetch(ctx, seq, i, fetches[seq])
			}
		}

		f := fetches[head]
		select {
		case <-f.ready:
		case <-r.grow:
			continue
		case <-ctx.Done():
			return
		}
		delete(fetches, head)
		if f.err != nil {
			r.setErr(f.err)
			return
		}
		if f.end {
			return
		}

		// the slot is free once the bytes are here, not once they are read
		r.mu.Lock()
		r.head++
		r.started = true
		r.mu.Unlock()
		errors.LogDebug(r.ctx, "xdrive read ", slotTag(r.table.Watermark), " seq=", head, " fetch=",
			f.readyAt.Sub(f.born), " blocked=", time.Since(f.readyAt), " bytes=", len(f.body),
			" reads=", r.reads.Load())
		if next := fetches[head+1]; next != nil {
			close(next.promoted)
			if nf := fetches[head+1+slotReadAhead]; nf != nil {
				nf.enter()
			}
		}
		select {
		case r.acks <- struct{}{}:
		default:
		}

		select {
		case r.ch <- f.body:
		case <-ctx.Done():
			return
		}
	}
}

func (r *slotReader) isHead(seq int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.head == seq
}

func (r *slotReader) bursting() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return time.Since(r.hitAt) <= slotReadAheadBurst
}

func (r *slotReader) reach(seq int64) {
	r.mu.Lock()
	grown := seq > r.frontier
	if grown {
		r.frontier = seq
	}
	r.mu.Unlock()
	if grown {
		select {
		case r.grow <- struct{}{}:
		default:
		}
	}
}

// fetch asks for the slot of seq until it holds seq: the head often, a segment
// behind it soon after it was asked for, then at the pace that segments come
func (r *slotReader) fetch(ctx context.Context, seq int64, offset int, f *slotFetch) {
	defer func() {
		f.readyAt = time.Now()
		close(f.ready)
	}()
	if offset > 0 && !r.hold(ctx, r.tailMin, f.promoted, f.near) {
		return
	}

	id := r.slotID(seq)
	backoff := slotHuntFloor
	var goneSince, warnedAt, visibleSince time.Time
	for {
		var description string
		var err error
		r.mu.Lock()
		hot := time.Since(r.activeAt) <= r.eagerWindow
		r.mu.Unlock()
		if hot && r.isHead(seq) {
			description, err = r.readHead(ctx, id, seq)
		} else {
			r.reads.Add(1)
			description, err = r.store.readDescription(ctx, id)
		}
		frame, ok := decodeSlot(description)
		if err == errNotFound || (err == nil && description == "") {
			// An absent or empty slot is idle, not a failure.
			visibleSince = time.Time{}
		}
		switch {
		case err == nil && ok && frame.seq == seq:
			// what follows it is asked for while its body comes
			r.mu.Lock()
			r.touch()
			r.mu.Unlock()
			r.reach(seq)
			switch frame.mode {
			case slotEnd:
				f.end = true
				return
			case slotErr:
				f.err = errors.New("the peer could not store segment ", seq)
				return
			case slotInline:
				f.body = frame.data
				r.hit()
				return
			case slotMedia:
				body, bodyErr := r.readBodyHedged(ctx, id, frame.size)
				if bodyErr == nil && frame.holds(body) {
					f.body = body
					r.hit()
					return
				}
				if ctx.Err() == nil && time.Since(warnedAt) > 10*time.Second {
					warnedAt = time.Now()
					if bodyErr != nil {
						errors.LogWarningInner(ctx, bodyErr, "failed to read body of slot ", id)
					} else {
						errors.LogWarning(ctx, "body of slot ", id, " does not match segment ", seq)
					}
				}
				if visibleSince.IsZero() {
					visibleSince = time.Now()
				}
				if time.Since(visibleSince) > r.stallTimeout {
					f.err = errors.New("segment ", seq, " has no usable body after ", r.stallTimeout).Base(bodyErr)
					return
				}
			}
		case err == nil && !ok && description != "":
			// A present but undecodable description for this slot is not idle;
			// fail once it has persisted beyond the stall timeout.
			if visibleSince.IsZero() {
				visibleSince = time.Now()
			}
			if time.Since(visibleSince) > r.stallTimeout {
				f.err = errors.New("slot ", id, " of segment ", seq, " holds an invalid frame")
				return
			}
		case err == errNotFound:
			if goneSince.IsZero() {
				goneSince = time.Now()
			} else if time.Since(goneSince) > slotGoneTimeout && r.isHead(seq) {
				f.err = errors.New("slot ", id, " of segment ", seq, " is gone").Base(err)
				return
			}
		case err != nil:
			if isAuthError(err) {
				f.err = err
				return
			}
			goneSince = time.Time{}
			if ctx.Err() == nil && time.Since(warnedAt) > 10*time.Second {
				warnedAt = time.Now()
				errors.LogWarningInner(ctx, err, "failed to read slot ", id)
			}
		}

		r.mu.Lock()
		head, idle, active := r.head == seq, time.Since(r.activeAt) > r.eagerWindow, r.active
		r.mu.Unlock()
		wait, a, b := backoff, (<-chan struct{})(r.wake), (<-chan struct{})(nil)
		switch {
		case head:
			ceiling := slotHuntCeiling
			if idle {
				ceiling = max(ceiling, r.maxPollInterval)
			}
			backoff = min(2*backoff, ceiling)
		case idle:
			// only the head is asked for until something comes
			wait, a, b, backoff = 0, f.promoted, active, slotHuntFloor
		default:
			wait, a, b, backoff = min(max(r.pace(), r.tailMin), r.tailMax), f.promoted, f.near, slotHuntFloor
			select {
			case <-f.near:
				b = nil
				if r.bursting() {
					wait = slotReadAheadPoll
				}
			default:
			}
		}
		if !r.hold(ctx, wait, a, b) {
			return
		}
	}
}

func (r *slotReader) readHead(ctx context.Context, id string, seq int64) (string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx = context.WithValue(ctx, laneKey{}, true)

	type result struct {
		description string
		err         error
	}
	results := make(chan result, 4)
	outstanding := 0
	launch := func() {
		outstanding++
		go func() {
			r.reads.Add(1)
			description, err := r.store.readDescription(ctx, id)
			results <- result{description, err}
		}()
	}
	launch()
	ticker := time.NewTicker(slotHuntCeiling)
	defer ticker.Stop()
	var last result
	seen := false
	for {
		select {
		case res := <-results:
			outstanding--
			if res.err != nil {
				return res.description, res.err
			}
			if frame, ok := decodeSlot(res.description); ok && frame.seq == seq {
				return res.description, nil
			}
			last, seen = res, true
		case <-ticker.C:
			r.mu.Lock()
			idle := time.Since(r.activeAt) > r.eagerWindow
			r.mu.Unlock()
			switch {
			case idle && seen:
				return last.description, nil
			case !idle && outstanding < 3:
				launch()
			}
		case <-r.wake:
			if outstanding < 3 {
				launch()
			}
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}

func (r *slotReader) readBodyHedged(ctx context.Context, id string, size int) ([]byte, error) {
	if slotBodyHedge <= 0 {
		return r.store.readBody(ctx, id)
	}
	delay := slotBodyHedge
	r.mu.Lock()
	rate := r.bodyRate
	r.mu.Unlock()
	if rate > 0 && size > 0 {
		if scaled := time.Duration(float64(2*size) / rate * float64(time.Second)); scaled > delay {
			delay = scaled
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	start := time.Now()

	type result struct {
		body []byte
		err  error
	}
	results := make(chan result, 2)
	launch := func() {
		go func() {
			body, err := r.store.readBody(ctx, id)
			results <- result{body, err}
		}()
	}
	launch()
	outstanding := 1
	timer := time.NewTimer(delay)
	defer timer.Stop()
	var last result
	for {
		select {
		case res := <-results:
			outstanding--
			if res.err == nil {
				if elapsed := time.Since(start); elapsed > 0 && len(res.body) > 0 {
					instant := float64(len(res.body)) / elapsed.Seconds()
					r.mu.Lock()
					if r.bodyRate == 0 {
						r.bodyRate = instant
					} else {
						r.bodyRate = (r.bodyRate + instant) / 2
					}
					r.mu.Unlock()
				}
				return res.body, nil
			}
			last = res
			if outstanding == 0 {
				return nil, last.err
			}
		case <-timer.C:
			if outstanding == 1 {
				launch()
				outstanding++
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// pace is about how long segments take to come one after the other
func (r *slotReader) pace() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return min(max(r.gap, 300*time.Millisecond), 3*time.Second)
}

func (r *slotReader) hit() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if gap := time.Since(r.hitAt); r.gap == 0 {
		r.gap = gap
	} else {
		r.gap = (r.gap + gap) / 2
	}
	r.hitAt = time.Now()
	r.touch()
}

// touch notes that something came or is likely to. r.mu is held
func (r *slotReader) touch() {
	if time.Since(r.activeAt) > r.eagerWindow {
		close(r.active)
		r.active = make(chan struct{})
	}
	r.activeAt = time.Now()
}

// hold waits d, unless d is 0, or until a or b is closed or has a value
func (r *slotReader) hold(ctx context.Context, d time.Duration, a, b <-chan struct{}) bool {
	var timeout <-chan time.Time
	if d > 0 {
		timer := time.NewTimer(d)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case <-ctx.Done():
		return false
	case <-a:
	case <-b:
	case <-timeout:
	}
	return true
}

// ackLoop writes the watermark when the head moves, the last head only if it
// moved more than once meanwhile
func (r *slotReader) ackLoop() {
	acked := int64(-1)
	wait := slotAckRetry
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-r.acks:
		}
		for {
			r.mu.Lock()
			want := r.head - 1
			r.mu.Unlock()
			if want <= acked {
				break
			}
			if err := r.store.setSlot(context.WithValue(r.ctx, laneKey{}, true), r.table.Watermark, strconv.FormatInt(want, 10), nil); err == nil {
				acked, wait = want, slotAckRetry
				continue
			}
			wait = min(2*wait, 5*time.Second)
			select {
			case <-r.ctx.Done():
				return
			case <-time.After(wait):
			}
		}
	}
}

func (r *slotReader) setErr(err error) {
	r.mu.Lock()
	if r.err == nil {
		r.err = err
	}
	r.mu.Unlock()
	// A stored error means the connection is dead: stop the run loop so the
	// chunk channel closes and Read returns the error instead of blocking.
	if r.stop != nil {
		r.stop()
	}
}

func (r *slotReader) Err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	return io.EOF
}

func slotTag(id string) string {
	if len(id) > 6 {
		return id[len(id)-6:]
	}
	return id
}
