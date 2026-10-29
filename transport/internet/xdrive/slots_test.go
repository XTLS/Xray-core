package xdrive

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"math/rand"
	"os"
	"strconv"
	"sync"
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
	client := newSlotConn(context.Background(), store, r.Up, r.Down, p, nil)
	server := newSlotConn(context.Background(), store, r.Down, r.Up, p, nil)
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
	writeAll(client, payload, true, errs)
	readAll(t, server, payload)
}
