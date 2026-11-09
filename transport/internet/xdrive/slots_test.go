package xdrive

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memSlots struct {
	mu     sync.Mutex
	next   int
	descs  map[string]string
	bodies map[string][]byte
	reads  int
}

func newMemSlots() *memSlots {
	return &memSlots{descs: make(map[string]string), bodies: make(map[string][]byte)}
}

func (m *memSlots) makeSlot(ctx context.Context, name string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	id := "slot-" + strconv.Itoa(m.next)
	m.descs[id] = ""
	return id, nil
}

func (m *memSlots) setSlot(ctx context.Context, id, description string, body []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.descs[id]; !ok {
		return errNotFound
	}
	m.descs[id] = description
	if body != nil {
		m.bodies[id] = bytes.Clone(body)
	}
	return nil
}

func (m *memSlots) readDescription(ctx context.Context, id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	d, ok := m.descs[id]
	if !ok {
		return "", errNotFound
	}
	return d, nil
}

func (m *memSlots) readBody(ctx context.Context, id string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bodies[id], nil
}

// the slots of all tests are asked for often, set once as a goroutine of a
// closed Conn may still read them
func init() {
	slotHuntFloor, slotHuntCeiling, slotTailMin, slotTailMax = 2*time.Millisecond, 10*time.Millisecond, 5*time.Millisecond, 20*time.Millisecond
	slotAckRetry, slotWatermarkTTL = 2*time.Millisecond, 2*time.Millisecond
}

func slotPair(t *testing.T, store slotStore, concurrency, segmentBytes uint32) (*Conn, *Conn) {
	t.Helper()
	p := paramsFromConfig(&Config{
		SegmentBytes:      segmentBytes,
		FlushIntervalMs:   1,
		PollIntervalMs:    1,
		MaxPollIntervalMs: 20,
		EagerWindowMs:     50,
		Concurrency:       concurrency,
	})
	r, err := makeRing(context.Background(), store, "session", p)
	if err != nil {
		t.Fatal(err)
	}
	client := newSlotConn(context.Background(), store, r.Up, r.Down, p, nil, nil)
	server := newSlotConn(context.Background(), store, r.Down, r.Up, p, nil, nil)
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	for _, c := range []*Conn{client, server} {
		c.SetReadDeadline(time.Now().Add(30 * time.Second))
	}
	return client, server
}

// writeAll writes payload in pieces of random size, and closes c if end, the
// error goes to errs
func writeAll(c *Conn, payload []byte, end bool, errs chan<- error) {
	go func() {
		rng := rand.New(rand.NewSource(1))
		for len(payload) > 0 {
			n := min(len(payload), 1+rng.Intn(40<<10))
			if _, err := c.Write(payload[:n]); err != nil {
				errs <- err
				return
			}
			payload = payload[n:]
		}
		var err error
		if end {
			err = c.Close()
		}
		errs <- err
	}()
}

func readAll(t *testing.T, c *Conn, want []byte) {
	t.Helper()
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %d bytes, not the %d that were sent", len(got), len(want))
	}
}

func randomPayload(n int) []byte {
	payload := make([]byte, n)
	rand.New(rand.NewSource(int64(n))).Read(payload)
	return payload
}

func TestSlotFrame(t *testing.T) {
	data := []byte("hello")
	f, ok := decodeSlot(newSlotFrame(7, slotInline, data).encode())
	if !ok || f.seq != 7 || f.mode != slotInline || !bytes.Equal(f.data, data) {
		t.Fatalf("inline frame came back as %+v %v", f, ok)
	}

	body := randomPayload(100)
	f, ok = decodeSlot(newSlotFrame(8, slotMedia, body).encode())
	if !ok || f.seq != 8 || f.mode != slotMedia || f.data != nil || !f.holds(body) || f.holds(body[1:]) {
		t.Fatalf("media frame came back as %+v %v", f, ok)
	}

	corrupt, _ := base64.StdEncoding.DecodeString(newSlotFrame(1, slotInline, data).encode())
	corrupt[len(corrupt)-1]++
	for _, broken := range []string{
		"", "not base64", newSlotFrame(1, slotInline, data).encode()[:20], "WERSVlNMMDE=",
		base64.StdEncoding.EncodeToString(corrupt),
	} {
		if _, ok := decodeSlot(broken); ok {
			t.Errorf("%q decoded", broken)
		}
	}
}

// both sides send more segments than the ring has slots at once, small ones
// that go in descriptions and large ones that go in bodies, then one closes
// and the other reads EOF
func TestSlotConnRoundTrip(t *testing.T) {
	client, server := slotPair(t, newMemSlots(), 4, 64<<10)
	up, down := randomPayload(1<<20), randomPayload(300<<10)
	errs := make(chan error, 2)
	writeAll(client, up, false, errs)
	writeAll(server, down, false, errs)

	for _, c := range []struct {
		conn *Conn
		want []byte
	}{{server, up}, {client, down}} {
		got := make([]byte, len(c.want))
		if _, err := io.ReadFull(c.conn, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, c.want) {
			t.Fatal("what came is not what was sent")
		}
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	readAll(t, server, nil)
}

// a reader that does not read holds the writer back instead of losing what a
// lap of the ring would overwrite
func TestSlotConnSlowReader(t *testing.T) {
	client, server := slotPair(t, newMemSlots(), 2, 16<<10)
	payload := randomPayload(400 << 10)
	errs := make(chan error, 1)
	writeAll(client, payload, true, errs)

	time.Sleep(200 * time.Millisecond)
	readAll(t, server, payload)
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
}

// the next segment is asked for at once when it becomes the head, not after
// the wait it had as one that was fetched ahead
func TestSlotLatency(t *testing.T) {
	client, server := slotPair(t, newMemSlots(), 8, 64<<10)
	start := time.Now()
	for range 10 {
		for _, c := range [][2]*Conn{{client, server}, {server, client}} {
			c[0].Write([]byte("ping"))
			if _, err := io.ReadFull(c[1], make([]byte, 4)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("10 round trips took %v", took)
	}
}

// once nothing comes for the eager window only the heads are asked for, not
// the segments that a reader fetches ahead while things come
func TestSlotIdle(t *testing.T) {
	store := newMemSlots()
	client, server := slotPair(t, store, 8, 64<<10)
	for _, c := range [][2]*Conn{{client, server}, {server, client}} {
		c[0].Write([]byte("ping"))
		if _, err := io.ReadFull(c[1], make([]byte, 4)); err != nil {
			t.Fatal(err)
		}
	}

	time.Sleep(200 * time.Millisecond)
	store.mu.Lock()
	before := store.reads
	store.mu.Unlock()
	time.Sleep(500 * time.Millisecond)
	store.mu.Lock()
	reads := store.reads - before
	store.mu.Unlock()
	// two heads, each asked for every 20 ms at most
	if reads > 75 {
		t.Fatalf("an idle session asked for slots %d times in 500 ms", reads)
	}
}

type failingSlots struct {
	*memSlots
}

// setSlot fails for segments, not for the error frame
func (f failingSlots) setSlot(ctx context.Context, id, description string, body []byte) error {
	if frame, ok := decodeSlot(description); ok && (frame.mode == slotInline || frame.mode == slotMedia) {
		return io.ErrUnexpectedEOF
	}
	return f.memSlots.setSlot(ctx, id, description, body)
}

func TestSlotWriterFailure(t *testing.T) {
	client, server := slotPair(t, failingSlots{newMemSlots()}, 2, 16<<10)
	client.Write([]byte("lost"))
	server.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := server.Read(make([]byte, 10)); err == nil || err == io.EOF || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the reader got %v, not the failure of the writer", err)
	}
	for start := time.Now(); time.Since(start) < 5*time.Second; time.Sleep(time.Millisecond) {
		if _, err := client.Write([]byte("more")); err != nil {
			return
		}
	}
	t.Fatal("Write did not fail")
}

type staleSlots struct {
	*memSlots
	mu     sync.Mutex
	served map[string]bool
}

// readBody gives what a slot held before once, as a body read right after its
// description may
func (s *staleSlots) readBody(ctx context.Context, id string) ([]byte, error) {
	s.mu.Lock()
	first := !s.served[id]
	s.served[id] = true
	s.mu.Unlock()
	if first {
		return []byte("stale"), nil
	}
	return s.memSlots.readBody(ctx, id)
}

func TestSlotStaleBody(t *testing.T) {
	client, server := slotPair(t, &staleSlots{memSlots: newMemSlots(), served: make(map[string]bool)}, 2, 64<<10)
	payload := randomPayload(200 << 10)
	errs := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		if err == nil {
			err = client.Close()
		}
		errs <- err
	}()
	readAll(t, server, payload)
}

func TestSlotBurstSplitsInline(t *testing.T) {
	store := newMemSlots()
	client, server := slotPair(t, store, 8, 512<<10)
	payload := randomPayload(90 << 10)
	errs := make(chan error, 1)
	writeAll(client, payload, true, errs)
	readAll(t, server, payload)
	store.mu.Lock()
	bodies := len(store.bodies)
	store.mu.Unlock()
	if bodies != 0 {
		t.Fatalf("a burst of 90 KiB went in %d bodies, want none", bodies)
	}
}

type stuckBodySlots struct {
	*memSlots
	calls atomic.Int32
}

func (s *stuckBodySlots) readBody(ctx context.Context, id string) ([]byte, error) {
	if s.calls.Add(1) == 1 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return s.memSlots.readBody(ctx, id)
}

func TestSlotBodyHedge(t *testing.T) {
	old := slotBodyHedge
	slotBodyHedge = 50 * time.Millisecond
	defer func() { slotBodyHedge = old }()

	store := &stuckBodySlots{memSlots: newMemSlots()}
	client, server := slotPair(t, store, 2, 64<<10)
	payload := randomPayload(200 << 10)
	errs := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		if err == nil {
			err = client.Close()
		}
		errs <- err
	}()
	readAll(t, server, payload)
	if store.calls.Load() < 2 {
		t.Fatalf("the stuck body read was not hedged, %d reads", store.calls.Load())
	}
}

type timedBodySlots struct {
	*memSlots
	calls atomic.Int32
	delay time.Duration
	stuck atomic.Bool
}

func (s *timedBodySlots) readBody(ctx context.Context, id string) ([]byte, error) {
	n := s.calls.Add(1)
	if s.stuck.Load() && n == 1 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(s.delay):
	}
	return make([]byte, 1000), nil
}

func TestSlotBodyHedgeRate(t *testing.T) {
	old := slotBodyHedge
	slotBodyHedge = 20 * time.Millisecond
	t.Cleanup(func() { slotBodyHedge = old })

	store := &timedBodySlots{memSlots: newMemSlots(), delay: 60 * time.Millisecond}
	r := &slotReader{store: store}
	ctx := context.Background()
	if _, err := r.readBodyHedged(ctx, "id", 1000); err != nil {
		t.Fatal(err)
	}
	store.calls.Store(0)
	start := time.Now()
	if _, err := r.readBodyHedged(ctx, "id", 1000); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 60*time.Millisecond {
		t.Fatalf("the progressing read returned in %v, before its body was ready", elapsed)
	}
	if n := store.calls.Load(); n != 1 {
		t.Fatalf("a progressing read after a learned slow rate hedged, %d reads", n)
	}

	r.mu.Lock()
	rate := r.bodyRate
	r.mu.Unlock()
	if rate <= 0 {
		t.Fatal("no body read rate was learned")
	}
	expected := max(slotBodyHedge, time.Duration(float64(2*1000)/rate*float64(time.Second)))
	store.stuck.Store(true)
	store.calls.Store(0)
	start = time.Now()
	if _, err := r.readBodyHedged(ctx, "id", 1000); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if n := store.calls.Load(); n < 2 {
		t.Fatalf("a stuck read after a learned rate was not hedged, %d reads", n)
	}
	if elapsed < expected/2 {
		t.Fatalf("the stuck read hedged after %v, want about %v", elapsed, expected)
	}

	freshStore := &timedBodySlots{memSlots: newMemSlots()}
	freshStore.stuck.Store(true)
	fresh := &slotReader{store: freshStore}
	store.calls.Store(0)
	start = time.Now()
	if _, err := fresh.readBodyHedged(ctx, "id", 1000); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < slotBodyHedge {
		t.Fatalf("with no learned rate the hedge came after %v, want at least %v", elapsed, slotBodyHedge)
	}
}

func TestTakeSpareSkipsStale(t *testing.T) {
	cfg := &Config{}
	p := params{sessionTTL: 5 * time.Minute}
	st1, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st2, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	box := spareBoxFor(cfg)
	box.ch <- spareRing{storage: st1, session: "old", at: time.Now().Add(-time.Hour)}
	box.ch <- spareRing{storage: st2, session: "new", at: time.Now()}
	got, ok := takeSpare(cfg, p)
	if !ok || got.session != "new" {
		t.Fatalf("takeSpare gave %q, %v, want the fresh one", got.session, ok)
	}
	if _, ok := takeSpare(cfg, p); ok {
		t.Fatal("takeSpare returned a second spare")
	}
}

func TestDropSpareDeletesSession(t *testing.T) {
	st, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	name := sessionPrefix("gone") + "/" + uplinkDir + "/s0"
	if err := st.Put(context.Background(), name, []byte("x")); err != nil {
		t.Fatal(err)
	}
	dropSpare(spareRing{storage: st, session: "gone"})
	if got, _ := st.List(context.Background(), sessionPrefix("gone")); len(got) != 0 {
		t.Fatalf("%d entries left of a dropped spare", len(got))
	}
}

type stuckHeadSlots struct {
	*memSlots
	calls atomic.Int32
}

func (s *stuckHeadSlots) readDescription(ctx context.Context, id string) (string, error) {
	if s.calls.Add(1) == 1 {
		<-ctx.Done()
		return "", ctx.Err()
	}
	return s.memSlots.readDescription(ctx, id)
}

func TestSlotHeadReadOverlaps(t *testing.T) {
	client, server := slotPair(t, &stuckHeadSlots{memSlots: newMemSlots()}, 4, 64<<10)
	for _, c := range [][2]*Conn{{client, server}, {server, client}} {
		c[0].Write([]byte("ping"))
		if _, err := io.ReadFull(c[1], make([]byte, 4)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSlotBurstReadsTogether(t *testing.T) {
	client, server := slotPair(t, newMemSlots(), 16, 512<<10)
	payload := randomPayload(8 * slotInlineLimit)
	go client.Write(payload)
	start := time.Now()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the burst came back changed")
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("a burst of 8 segments took %v to read", took)
	}
}

type lagSlots struct{ *memSlots }

func (s lagSlots) readDescription(ctx context.Context, id string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(200 * time.Millisecond):
	}
	return s.memSlots.readDescription(ctx, id)
}

func (s lagSlots) setSlot(ctx context.Context, id, description string, body []byte) error {
	if _, ok := decodeSlot(description); ok {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(600 * time.Millisecond):
		}
	}
	return s.memSlots.setSlot(ctx, id, description, body)
}

func TestSlotReadAheadBurst(t *testing.T) {
	oldMin, oldMax := slotTailMin, slotTailMax
	slotTailMin, slotTailMax = 150*time.Millisecond, 800*time.Millisecond
	t.Cleanup(func() { slotTailMin, slotTailMax = oldMin, oldMax })

	client, server := slotPair(t, lagSlots{newMemSlots()}, 16, 512<<10)
	payload := randomPayload(8 * slotInlineLimit)
	go client.Write(payload)
	start := time.Now()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the burst came back changed")
	}
	if took := time.Since(start); took > 1700*time.Millisecond {
		t.Fatalf("a burst of 8 segments took %v to read", took)
	}
	client.Close()
	server.Close()
}

func TestSlotLargeBurstInline(t *testing.T) {
	store := newMemSlots()
	client, server := slotPair(t, store, 16, 512<<10)
	payload := randomPayload(10 * slotInlineLimit)
	go client.Write(payload)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the burst came back changed")
	}
	store.mu.Lock()
	bodies := len(store.bodies)
	store.mu.Unlock()
	if bodies != 0 {
		t.Fatalf("a burst of 140 KiB went in %d bodies, want none", bodies)
	}
}

func TestSlotDepthFollowsConcurrency(t *testing.T) {
	for _, c := range []struct{ set, want int }{{100, 100}, {maxConcurrency, maxConcurrency}, {1 << 20, maxConcurrency}} {
		p := paramsFromConfig(&Config{Concurrency: uint32(c.set)})
		r, err := makeRing(context.Background(), newMemSlots(), "session", p)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Up.Slots) != c.want || len(r.Down.Slots) != c.want {
			t.Fatalf("concurrency %d made %d and %d slots, want %d", c.set, len(r.Up.Slots), len(r.Down.Slots), c.want)
		}
	}
}

func TestSlotDeepRingRoundTrip(t *testing.T) {
	client, server := slotPair(t, newMemSlots(), 64, 64<<10)
	payload := randomPayload(2 << 20)
	errs := make(chan error, 1)
	writeAll(client, payload, true, errs)
	readAll(t, server, payload)
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
}

type pollSlots struct {
	*memSlots
	pmu    sync.Mutex
	polled map[string]bool
}

func (s *pollSlots) readDescription(ctx context.Context, id string) (string, error) {
	s.pmu.Lock()
	s.polled[id] = true
	s.pmu.Unlock()
	return s.memSlots.readDescription(ctx, id)
}

func TestSlotReaderReachesPastWindow(t *testing.T) {
	store := &pollSlots{memSlots: newMemSlots(), polled: make(map[string]bool)}
	p := paramsFromConfig(&Config{FlushIntervalMs: 1, PollIntervalMs: 1, MaxPollIntervalMs: 20, EagerWindowMs: 50, Concurrency: 64})
	ring, err := makeRing(context.Background(), store, "session", p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	put := func(seq int64) {
		slot := ring.Down.Slots[seq%int64(len(ring.Down.Slots))]
		if err := store.setSlot(ctx, slot, newSlotFrame(seq, slotInline, []byte{byte(seq)}).encode(), nil); err != nil {
			t.Fatal(err)
		}
	}
	reader := newSlotReader(ctx, store, ring.Down, p, nil)
	next := func() []byte {
		select {
		case chunk := <-reader.chunks():
			return chunk
		case <-time.After(10 * time.Second):
			t.Fatal("no segment came")
			return nil
		}
	}
	put(0)
	if got := next(); !bytes.Equal(got, []byte{0}) {
		t.Fatalf("segment 0 came as %v", got)
	}
	for seq := int64(2); seq <= 40; seq++ {
		put(seq)
	}
	last := ring.Down.Slots[40]
	deadline := time.Now().Add(10 * time.Second)
	for {
		reader.Wake()
		store.pmu.Lock()
		polled := store.polled[last]
		store.pmu.Unlock()
		if polled {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("segment 40 was never asked for while segment 1 was missing")
		}
		time.Sleep(10 * time.Millisecond)
	}
	put(1)
	for seq := int64(1); seq <= 40; seq++ {
		if got := next(); !bytes.Equal(got, []byte{byte(seq)}) {
			t.Fatalf("segment %d came as %v", seq, got)
		}
	}
}

type countSlots struct {
	*memSlots
	cur  atomic.Int32
	peak atomic.Int32
}

func (s *countSlots) setSlot(ctx context.Context, id, description string, body []byte) error {
	if _, ok := decodeSlot(description); !ok {
		return s.memSlots.setSlot(ctx, id, description, body)
	}
	n := s.cur.Add(1)
	for {
		p := s.peak.Load()
		if n <= p || s.peak.CompareAndSwap(p, n) {
			break
		}
	}
	time.Sleep(20 * time.Millisecond)
	s.cur.Add(-1)
	return s.memSlots.setSlot(ctx, id, description, body)
}

func TestSlotWriteInflightCap(t *testing.T) {
	store := &countSlots{memSlots: newMemSlots()}
	client, server := slotPair(t, store, 48, 512<<10)
	payload := randomPayload(60 * slotInlineLimit)
	errs := make(chan error, 1)
	go func() {
		for off := 0; off < len(payload); off += slotInlineLimit {
			if _, err := client.Write(payload[off : off+slotInlineLimit]); err != nil {
				errs <- err
				return
			}
		}
		errs <- nil
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the payload came back changed")
	}
	if p := int(store.peak.Load()); p > slotWriteInflight {
		t.Fatalf("%d segments were written at once, want at most %d", p, slotWriteInflight)
	}
}

func TestSlotBurstInlineWaves(t *testing.T) {
	for _, c := range []struct {
		pieces int
		media  bool
	}{{20, false}, {30, true}} {
		store := newMemSlots()
		client, server := slotPair(t, store, 16, 512<<10)
		payload := randomPayload(c.pieces * slotInlineLimit)
		go client.Write(payload)
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(server, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("the burst came back changed")
		}
		store.mu.Lock()
		bodies := len(store.bodies)
		store.mu.Unlock()
		if (bodies > 0) != c.media {
			t.Fatalf("a burst of %d pieces went in %d bodies, media wanted %v", c.pieces, bodies, c.media)
		}
	}
}

type holdSlots struct {
	*memSlots
	target string
	hold   chan struct{}
}

func (s *holdSlots) setSlot(ctx context.Context, id, description string, body []byte) error {
	if id == s.target {
		select {
		case <-s.hold:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.memSlots.setSlot(ctx, id, description, body)
}

func TestSlotFirstAnnouncement(t *testing.T) {
	p := params{
		concurrency:     2,
		segmentBytes:    4096,
		flushInterval:   time.Millisecond,
		minPollInterval: time.Millisecond,
		maxPollInterval: 5 * time.Millisecond,
		sessionTTL:      time.Minute,
	}
	store := &holdSlots{memSlots: newMemSlots(), hold: make(chan struct{})}
	ctx := context.Background()
	r, err := makeRing(ctx, store, "first", p)
	if err != nil {
		t.Fatal(err)
	}
	store.target = r.Up.Slots[0]
	client := newSlotConn(ctx, store, r.Up, r.Down, p, nil, nil)
	defer client.Close()
	writer := client.writer.(*slotWriter)
	writer.first = make(chan []byte, 1)

	payload := randomPayload(10000)
	errs := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		if err == nil {
			err = client.Close()
		}
		errs <- err
	}()
	var first []byte
	select {
	case first = <-writer.first:
	case <-time.After(5 * time.Second):
		t.Fatal("the writer never flushed seq 0")
	}
	announced := r
	announced.First = first
	encoded, err := json.Marshal(announced)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > driveInlineLimit {
		t.Fatalf("the test announcement is %d bytes, want the inline path", len(encoded))
	}
	decoded, ok := decodeRing(encoded)
	if !ok {
		t.Fatal("the announcement with First did not decode")
	}
	server := newSlotConn(ctx, store, decoded.Down, decoded.Up, p, decoded.First, nil)
	defer server.Close()
	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	gotFirst := make([]byte, len(first))
	if _, err := io.ReadFull(server, gotFirst); err != nil {
		t.Fatalf("the first bytes did not arrive before the ring write: %v", err)
	}
	if !bytes.Equal(gotFirst, first) {
		t.Fatal("the primed first bytes changed")
	}
	close(store.hold)
	rest := make([]byte, len(payload)-len(first))
	if _, err := io.ReadFull(server, rest); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(gotFirst, rest...), payload) {
		t.Fatal("the stream was duplicated or changed")
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
}

func TestSlotFirstAnnouncementTooLarge(t *testing.T) {
	p := params{
		concurrency:   2,
		segmentBytes:  256 << 10,
		flushInterval: time.Millisecond,
		sessionTTL:    time.Minute,
	}
	store := newMemSlots()
	ctx := context.Background()
	r, err := makeRing(ctx, store, "large-first", p)
	if err != nil {
		t.Fatal(err)
	}
	client := newSlotConn(ctx, store, r.Up, r.Down, p, nil, nil)
	defer client.Close()
	writer := client.writer.(*slotWriter)
	writer.first = make(chan []byte, 1)
	go client.Write(randomPayload(300 << 10))
	var first []byte
	select {
	case first = <-writer.first:
	case <-time.After(5 * time.Second):
		t.Fatal("the writer never flushed seq 0")
	}
	if len(first) <= slotInlineLimit {
		t.Fatalf("the first segment is %d bytes, want a media segment", len(first))
	}
	withFirst := r
	withFirst.First = first
	encoded, err := json.Marshal(withFirst)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) <= driveInlineLimit {
		t.Fatalf("a %d byte first segment fit the inline announcement", len(first))
	}
	plain, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	decoded, ok := decodeRing(plain)
	if !ok || decoded.First != nil {
		t.Fatal("the announcement without First did not decode cleanly")
	}
}

func TestSlotRingFirstCompatibility(t *testing.T) {
	p := params{concurrency: 2, sessionTTL: time.Minute}
	store := newMemSlots()
	r, err := makeRing(context.Background(), store, "compat", p)
	if err != nil {
		t.Fatal(err)
	}
	r.First = []byte("hello")
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var oldServer struct {
		Up   slotTable `json:"u"`
		Down slotTable `json:"d"`
	}
	if err := json.Unmarshal(encoded, &oldServer); err != nil {
		t.Fatalf("an old server could not ignore First: %v", err)
	}
	if len(oldServer.Up.Slots) != len(r.Up.Slots) || len(oldServer.Down.Slots) != len(r.Down.Slots) {
		t.Fatal("an old server lost the ring tables")
	}
	r.First = nil
	plain, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	decoded, ok := decodeRing(plain)
	if !ok || decoded.First != nil {
		t.Fatal("an old client announcement did not decode")
	}
}
