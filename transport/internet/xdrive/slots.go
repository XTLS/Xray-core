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
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// A session on a slotStore is carried in a ring of slots for each direction,
// objects that both peers know by id: segment n is written to slot n % depth
// and read from it, with nothing to list and no index to wait for. The reader
// of a direction keeps how far it has read in a watermark, and the writer
// reuses a slot only once that says what was in it before was taken

const (
	slotMagic = "XDRVSL02"
	// slotMagicV1 frames have no checksum, they are still read
	slotMagicV1   = "XDRVSL01"
	slotHeaderLen = len(slotMagic) + 8 + 1 + 4 + 4
	// slotHeaderLenV1 is the header without the checksum
	slotHeaderLenV1 = len(slotMagicV1) + 8 + 1 + 4
	// slotInlineLimit is how large a segment is at most to go in the description
	// of its slot, which takes one request less than a body
	slotInlineLimit = 14 << 10
	slotDepthLimit  = 16
	// inlineRampSegments segments of one size in a row double it, from
	// slotInlineLimit up to segmentBytes
	inlineRampSegments = 8

	slotInline = 1
	slotMedia  = 2
	slotEnd    = 3
	slotErr    = 4
)

var (
	// the head is asked for between slotHuntFloor and slotHuntCeiling, a segment
	// behind it at about the pace that segments come
	slotHuntFloor   = 50 * time.Millisecond
	slotHuntCeiling = 100 * time.Millisecond
	slotTailMin     = 150 * time.Millisecond
	slotTailMax     = 800 * time.Millisecond
	slotFetchAhead  = 10

	slotAckRetry     = 30 * time.Millisecond
	slotWatermarkTTL = 100 * time.Millisecond
	slotStallTimeout = 60 * time.Second
	slotCloseGrace   = 10 * time.Second
	slotGoneTimeout  = 60 * time.Second

	// a failed write of a segment is tried slotWriteAttempts times
	slotWriteAttempts = 3
	// a read of the head that has not answered for slotHedgeTick is asked a
	// second time, for slotHedgeBudget at most
	slotHedgeTick   = 250 * time.Millisecond
	slotHedgeBudget = time.Second
)

// slotStore is a storage of objects that are written and read again by id,
// each with a description and a body
type slotStore interface {
	makeSlot(ctx context.Context, name string) (string, error)
	// setSlot sets the description of a slot and, unless body is nil, its body
	setSlot(ctx context.Context, id, description string, body []byte) error
	readDescription(ctx context.Context, id string) (string, error)
	readBody(ctx context.Context, id string) ([]byte, error)
}

// slotFrame is what the description of a slot says: which segment it holds,
// and either the segment itself or the size and checksum of the body that does
type slotFrame struct {
	seq  int64
	mode byte
	size int
	crc  uint32
	data []byte
	// legacy frames carry no checksum
	legacy bool
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
	if err != nil || len(b) < slotHeaderLenV1 {
		return slotFrame{}, false
	}
	switch string(b[:len(slotMagic)]) {
	case slotMagic:
		return decodeSlotV2(b)
	case slotMagicV1:
		return decodeSlotV1(b)
	}
	return slotFrame{}, false
}

func decodeSlotV2(b []byte) (slotFrame, bool) {
	if len(b) < slotHeaderLen {
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

func decodeSlotV1(b []byte) (slotFrame, bool) {
	f := slotFrame{
		seq:  int64(binary.BigEndian.Uint64(b[8:])),
		mode: b[16],
		size: int(binary.BigEndian.Uint32(b[17:])),

		legacy: true,
	}
	if f.mode == slotInline {
		f.data = b[slotHeaderLenV1:]
		if len(f.data) != f.size {
			return slotFrame{}, false
		}
		f.crc = crc32.ChecksumIEEE(f.data)
	}
	return f, true
}

// holds reports whether body is the one that f is about, which a body read
// right after its description need not be yet
func (f slotFrame) holds(body []byte) bool {
	return len(body) == f.size && (f.legacy || crc32.ChecksumIEEE(body) == f.crc)
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
	Up   slotTable `json:"u"`
	Down slotTable `json:"d"`
}

func decodeRing(b []byte) (ring, bool) {
	var r ring
	if json.Unmarshal(b, &r) != nil || len(r.Up.Slots) == 0 || len(r.Down.Slots) == 0 ||
		r.Up.Watermark == "" || r.Down.Watermark == "" {
		return ring{}, false
	}
	return r, true
}

// makeRing makes the slots and watermarks of a session, all at once
func makeRing(ctx context.Context, store slotStore, session string, p params) (ring, error) {
	depth := min(max(p.concurrency, 2), slotDepthLimit)
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
	d, err := store.readDescription(ctx, id)
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
	// slots has a token for each segment on its way, at most one for each slot
	slots chan struct{}
	wg    sync.WaitGroup

	mu       sync.Mutex
	buf      []byte
	seq      int64
	size     int
	full     int
	lastSize int
	held     int
	closed   bool
	err      error

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
		slots:    make(chan struct{}, len(table.Slots)),
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
	if w.closed {
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

	// slots are busy and the buffer small, so a bigger segment is worth the wait
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
	if w.err != nil || len(w.buf) == 0 {
		<-w.slots
		return w.err
	}

	// a ring three quarters busy is saturated by small segments, so widen at once
	if w.size < w.segmentBytes && len(w.buf) >= w.size && len(w.slots)*4 > cap(w.slots)*3 {
		w.size = w.segmentBytes
		w.full = 0
	}

	n := min(len(w.buf), w.size)
	if len(w.buf) > 4*slotInlineLimit {
		// a burst goes at the full size at once
		n = min(len(w.buf), w.segmentBytes)
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
	w.lastSize = len(w.buf)
	w.held = 0

	w.wg.Add(1)
	go w.upload(seq, chunk)
	return nil
}

func (w *slotWriter) slotID(seq int64) string {
	return w.table.Slots[seq%int64(len(w.table.Slots))]
}

func (w *slotWriter) upload(seq int64, chunk []byte) {
	defer w.wg.Done()
	defer func() { <-w.slots }()

	mode := byte(slotMedia)
	if len(chunk) <= slotInlineLimit {
		mode = slotInline
	}
	if err := w.await(seq); err != nil {
		w.fail(errors.New("failed to store segment ", seq).Base(err))
		return
	}
	var lastErr error
	for attempt := range slotWriteAttempts {
		if attempt > 0 {
			select {
			case <-w.ctx.Done():
				return
			case <-time.After(time.Duration(attempt) * 200 * time.Millisecond):
			}
			// the failed write may have gone through
			if d, err := w.store.readDescription(w.ctx, w.slotID(seq)); err == nil {
				if f, ok := decodeSlot(d); ok && f.seq >= seq {
					return
				}
			}
		}
		if lastErr = w.write(seq, mode, chunk); lastErr == nil {
			return
		}
		if w.ctx.Err() != nil {
			return
		}
	}
	w.fail(errors.New("failed to store segment ", seq).Base(lastErr))
	// the slot is free, the reader learns there what happened
	w.write(seq, slotErr, nil)
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

	mu      sync.Mutex
	head    int64
	started bool
	// hitAt is when a segment last came and gap the time between them, activeAt
	// when a segment came, was seen coming or Wake. Nothing for the eager window
	// is idle, and active is closed when that ends
	hitAt    time.Time
	gap      time.Duration
	activeAt time.Time
	active   chan struct{}
	err      error
}

func newSlotReader(ctx context.Context, store slotStore, table slotTable, p params) *slotReader {
	r := &slotReader{
		ctx:      ctx,
		store:    store,
		table:    table,
		params:   p,
		ch:       make(chan []byte, p.concurrency),
		wake:     make(chan struct{}, 1),
		acks:     make(chan struct{}, 1),
		hitAt:    time.Now(),
		activeAt: time.Now(),
		active:   make(chan struct{}),
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
	body     []byte
	end      bool
	err      error
}

func (r *slotReader) run() {
	defer close(r.ch)
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()

	fetches := make(map[int64]*slotFetch)
	for {
		r.mu.Lock()
		head, started := r.head, r.started
		r.mu.Unlock()

		window := 1
		if started {
			window = min(slotFetchAhead, len(r.table.Slots))
		}
		for i := range window {
			seq := head + int64(i)
			if fetches[seq] == nil {
				fetches[seq] = &slotFetch{ready: make(chan struct{}), promoted: make(chan struct{})}
				go r.fetch(ctx, seq, i, fetches[seq])
			}
		}

		f := fetches[head]
		select {
		case <-f.ready:
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
		if next := fetches[head+1]; next != nil {
			close(next.promoted)
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

// fetch asks for the slot of seq until it holds seq: the head often, a segment
// behind it at the pace that segments come, as it would wait for the head anyway
func (r *slotReader) fetch(ctx context.Context, seq int64, offset int, f *slotFetch) {
	defer close(f.ready)
	if offset > 0 && !r.hold(ctx, time.Duration(offset)*r.pace(), f.promoted, nil) {
		return
	}

	id := r.slotID(seq)
	backoff := slotHuntFloor
	var goneSince, warnedAt time.Time
	for {
		var description string
		var err error
		if r.isHead(seq) {
			description, err = r.readHedged(ctx, id)
		} else {
			description, err = r.store.readDescription(ctx, id)
		}
		frame, ok := decodeSlot(description)
		switch {
		case err == nil && ok && frame.seq == seq:
			// what follows it is asked for while its body comes
			r.mu.Lock()
			r.touch()
			r.mu.Unlock()
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
				if body, err := r.store.readBody(ctx, id); err == nil && frame.holds(body) {
					f.body = body
					r.hit()
					return
				}
			}
		case err == errNotFound:
			if goneSince.IsZero() {
				goneSince = time.Now()
			} else if time.Since(goneSince) > slotGoneTimeout && r.isHead(seq) {
				f.err = errors.New("slot ", id, " of segment ", seq, " is gone").Base(err)
				return
			}
		case err != nil:
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
			wait, a, backoff = min(max(r.pace(), slotTailMin), slotTailMax), f.promoted, slotHuntFloor
		}
		if !r.hold(ctx, wait, a, b) {
			return
		}
	}
}

// readHedged reads the description of the head, and asks a second time if the
// first request is slow to answer, as one that is stuck costs more than one
// too many. The first good answer is taken
func (r *slotReader) readHedged(ctx context.Context, id string) (string, error) {
	if slotHedgeTick <= 0 {
		return r.store.readDescription(ctx, id)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		description string
		err         error
	}
	results := make(chan result, 2)
	launch := func() {
		go func() {
			d, err := r.store.readDescription(ctx, id)
			results <- result{d, err}
		}()
	}
	launch()
	outstanding := 1
	deadline := time.Now().Add(slotHedgeBudget)
	ticker := time.NewTicker(slotHedgeTick)
	defer ticker.Stop()
	var last result
	for {
		select {
		case res := <-results:
			outstanding--
			if res.err == nil {
				return res.description, nil
			}
			last = res
			if outstanding == 0 {
				return last.description, last.err
			}
		case <-ticker.C:
			if outstanding < 2 && time.Now().Before(deadline) {
				launch()
				outstanding++
			}
		case <-ctx.Done():
			return "", ctx.Err()
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
			if err := r.store.setSlot(r.ctx, r.table.Watermark, strconv.FormatInt(want, 10), nil); err == nil {
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
	defer r.mu.Unlock()
	if r.err == nil {
		r.err = err
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
