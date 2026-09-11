package xdrive

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const testPatience = 30 * time.Second

func settings(folder string) *internet.MemoryStreamConfig {
	return &internet.MemoryStreamConfig{
		ProtocolName: protocolName,
		ProtocolSettings: &Config{
			RemoteFolder:      folder,
			Service:           "local",
			FlushIntervalMs:   5,
			PollIntervalMs:    5,
			MaxPollIntervalMs: 20,
			SessionTtlSeconds: 5,
		},
	}
}

func pair(t *testing.T) (client, server stat.Connection, cleanup func()) {
	t.Helper()
	return pairWith(t, settings(t.TempDir()))
}

func pairWith(t *testing.T, streamSettings *internet.MemoryStreamConfig) (client, server stat.Connection, cleanup func()) {
	t.Helper()

	accepted := make(chan stat.Connection, 1)

	listener, err := Serve(context.Background(), net.LocalHostIP, net.Port(0), streamSettings, func(conn stat.Connection) {
		accepted <- conn
	})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}

	client, err = Dial(context.Background(), net.Destination{}, streamSettings)
	if err != nil {
		listener.Close()
		t.Fatalf("Dial: %v", err)
	}

	select {
	case server = <-accepted:
	case <-time.After(testPatience):
		client.Close()
		listener.Close()
		t.Fatal("the listener never accepted the dialed session")
	}

	return client, server, func() {
		client.Close()
		server.Close()
		listener.Close()
	}
}

func expectRead(t *testing.T, conn stat.Connection, want string) {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(testPatience)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != want {
		t.Fatalf("read %q, want %q", buf, want)
	}
}

func TestRoundTrip(t *testing.T) {
	client, server, cleanup := pair(t)
	defer cleanup()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	expectRead(t, server, "ping")

	if _, err := server.Write([]byte("pong")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	expectRead(t, client, "pong")
}

func TestInterleavedMessages(t *testing.T) {
	client, server, cleanup := pair(t)
	defer cleanup()

	for i := 0; i < 20; i++ {
		if _, err := client.Write([]byte("up")); err != nil {
			t.Fatalf("client write %d: %v", i, err)
		}
		expectRead(t, server, "up")

		if _, err := server.Write([]byte("down")); err != nil {
			t.Fatalf("server write %d: %v", i, err)
		}
		expectRead(t, client, "down")
	}
}

func TestTransferAcrossSegments(t *testing.T) {
	client, server, cleanup := pair(t)
	defer cleanup()

	payload := make([]byte, 3*defaultSegmentBytes+1234)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	go func() {
		client.Write(payload)
	}()

	if err := server.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the received payload differs from the one that was sent")
	}
}

func TestCloseIsReportedAsEOF(t *testing.T) {
	client, server, cleanup := pair(t)
	defer cleanup()

	if _, err := client.Write([]byte("bye")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got, err := io.ReadAll(server)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "bye" {
		t.Fatalf("read %q, want %q", got, "bye")
	}
}

func TestReadDeadline(t *testing.T) {
	client, _, cleanup := pair(t)
	defer cleanup()

	if err := client.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := client.Read(buf); !os.IsTimeout(err) {
		t.Fatalf("Read returned %v, want a timeout", err)
	}
}

func TestLocalStorageRejectsEscapingNames(t *testing.T) {
	root := t.TempDir()
	storage, err := newLocalStorage(root)
	if err != nil {
		t.Fatalf("newLocalStorage: %v", err)
	}

	if err := storage.Put(context.Background(), "../escaped", []byte("x")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := os.Stat(root + "/escaped"); err != nil {
		t.Fatalf("the name should have been clamped inside the root: %v", err)
	}
}

func TestLocalStorageReportsMissingObjects(t *testing.T) {
	storage, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatalf("newLocalStorage: %v", err)
	}

	if _, err := storage.Get(context.Background(), "nothing/here"); err != errNotFound {
		t.Fatalf("Get returned %v, want errNotFound", err)
	}
	names, err := storage.List(context.Background(), "nothing")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("List returned %v, want nothing", names)
	}
}

func TestResumesAfterIdleBackoff(t *testing.T) {
	client, server, cleanup := pair(t)
	defer cleanup()

	if _, err := client.Write([]byte("first")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	expectRead(t, server, "first")

	time.Sleep(200 * time.Millisecond)

	if _, err := client.Write([]byte("second")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	expectRead(t, server, "second")
}

func TestParseEntry(t *testing.T) {
	cases := []struct {
		name string
		seq  int64
		ok   bool
	}{
		{"000000000.seg", 0, true},
		{"000000042.seg", 42, true},
		{"000000007.end", 7, true},
		{"000000001.tmp", 0, false},
		{"notanumber.seg", 0, false},
		{"000000001", 0, false},
	}
	for _, c := range cases {
		seq, ok := parseEntry(c.name)
		if ok != c.ok || (ok && seq != c.seq) {
			t.Fatalf("parseEntry(%q) = %d, %v; want %d, %v", c.name, seq, ok, c.seq, c.ok)
		}
	}
}

func TestParamsFallBackToDefaults(t *testing.T) {
	p := paramsFromConfig(&Config{})
	if p.segmentBytes != defaultSegmentBytes || p.flushInterval != defaultFlushInterval {
		t.Fatalf("defaults were not applied: %+v", p)
	}

	p = paramsFromConfig(&Config{SegmentBytes: 1 << 30, PollIntervalMs: 400, MaxPollIntervalMs: 100})
	if p.segmentBytes != maxSegmentBytes {
		t.Fatalf("segmentBytes is %d, want it clamped to %d", p.segmentBytes, maxSegmentBytes)
	}
	if p.maxPollInterval < p.minPollInterval {
		t.Fatalf("maxPollInterval %v must not be below minPollInterval %v", p.maxPollInterval, p.minPollInterval)
	}
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if done() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func newTestListener(t *testing.T, folder string) *Listener {
	t.Helper()

	storage, err := newLocalStorage(folder)
	if err != nil {
		t.Fatalf("newLocalStorage: %v", err)
	}
	return &Listener{
		ctx:       context.Background(),
		storage:   storage,
		params:    paramsFromConfig(&Config{SessionTtlSeconds: 1}),
		active:    make(map[string]bool),
		handled:   make(map[string]time.Time),
		idleSince: make(map[string]time.Time),
	}
}

func TestCollectRemovesAbandonedSessions(t *testing.T) {
	folder := t.TempDir()
	listener := newTestListener(t, folder)

	if err := listener.storage.Put(context.Background(), uplinkPrefix("dead")+"/000000000.seg", []byte("x")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if err := listener.collect(); err != nil {
		t.Fatalf("collect: %v", err)
	}
	names, _ := listener.storage.List(context.Background(), streamsDir)
	if len(names) != 1 {
		t.Fatalf("the first pass should only mark the session, got %v", names)
	}

	listener.idleSince["dead"] = time.Now().Add(-2 * time.Second)
	if err := listener.collect(); err != nil {
		t.Fatalf("collect: %v", err)
	}
	names, _ = listener.storage.List(context.Background(), streamsDir)
	if len(names) != 0 {
		t.Fatalf("the abandoned session should have been removed, got %v", names)
	}
}

func TestCollectKeepsActiveSessions(t *testing.T) {
	folder := t.TempDir()
	listener := newTestListener(t, folder)
	listener.active["live"] = true

	if err := listener.storage.Put(context.Background(), uplinkPrefix("live")+"/000000000.seg", []byte("x")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	listener.idleSince["live"] = time.Now().Add(-2 * time.Second)
	if err := listener.collect(); err != nil {
		t.Fatalf("collect: %v", err)
	}
	names, _ := listener.storage.List(context.Background(), streamsDir)
	if len(names) != 1 {
		t.Fatalf("an active session must not be collected, got %v", names)
	}
}

func TestParseAnnounce(t *testing.T) {
	session, at, ok := parseAnnounce("1757000000123456789-abc123")
	if !ok || session != "abc123" || at.UnixNano() != 1757000000123456789 {
		t.Fatalf("parseAnnounce returned %q, %v, %v", session, at.UnixNano(), ok)
	}
	for _, bad := range []string{"abc123", "-abc123", "1757000000-", "notanumber-abc"} {
		if _, _, ok := parseAnnounce(bad); ok {
			t.Fatalf("parseAnnounce accepted %q", bad)
		}
	}
}

func TestStaleAnnouncementIsDropped(t *testing.T) {
	folder := t.TempDir()
	listener := newTestListener(t, folder)

	ctx := context.Background()
	stale := announceName("ghost", time.Now().Add(-time.Hour))
	if err := listener.storage.Put(ctx, stale, nil); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := listener.storage.Put(ctx, uplinkPrefix("ghost")+"/000000000.seg", []byte("x")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	accepted, err := listener.acceptPending(ctx)
	if err != nil {
		t.Fatalf("acceptPending: %v", err)
	}
	if accepted {
		t.Fatal("a stale announcement must not be accepted")
	}

	waitFor(t, "the stale announcement to be removed", func() bool {
		names, _ := listener.storage.List(ctx, sessionsDir)
		return len(names) == 0
	})
	waitFor(t, "the stale session data to be removed", func() bool {
		names, _ := listener.storage.List(ctx, streamsDir)
		return len(names) == 0
	})
}

func TestFreshAnnouncementIsAccepted(t *testing.T) {
	folder := t.TempDir()
	listener := newTestListener(t, folder)
	listener.addConn = func(conn stat.Connection) { conn.Close() }

	ctx := context.Background()
	if err := listener.storage.Put(ctx, announceName("fresh", time.Now()), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}

	accepted, err := listener.acceptPending(ctx)
	if err != nil {
		t.Fatalf("acceptPending: %v", err)
	}
	if !accepted {
		t.Fatal("a fresh announcement should have been accepted")
	}
}

func TestAnnouncementKeepsSubSecondPrecision(t *testing.T) {
	at := time.Unix(1757000000, int64(900*time.Millisecond))
	entry := strings.TrimPrefix(announceName("abc123", at), sessionsDir+"/")

	session, parsed, ok := parseAnnounce(entry)
	if !ok || session != "abc123" {
		t.Fatalf("parseAnnounce(%q) returned %q, %v", entry, session, ok)
	}
	if !parsed.Equal(at) {
		t.Fatalf("the timestamp came back as %v, want %v", parsed, at)
	}
}

func TestRecentAnnouncementSurvivesAShortTTL(t *testing.T) {
	folder := t.TempDir()
	listener := newTestListener(t, folder)
	listener.addConn = func(conn stat.Connection) { conn.Close() }

	ctx := context.Background()
	recent := time.Now().Add(-900 * time.Millisecond)
	if err := listener.storage.Put(ctx, announceName("recent", recent), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}

	accepted, err := listener.acceptPending(ctx)
	if err != nil {
		t.Fatalf("acceptPending: %v", err)
	}
	if !accepted {
		t.Fatal("an announcement younger than the TTL must still be accepted")
	}
}

func TestReaderGivesUpOnAMissingSegment(t *testing.T) {
	storage, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatalf("newLocalStorage: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := paramsFromConfig(&Config{PollIntervalMs: 5, MaxPollIntervalMs: 20, HoleTimeoutMs: 200})
	if err := storage.Put(ctx, segmentName("hole", 1), []byte("second")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	reader := newWALReader(ctx, storage, "hole", p)
	select {
	case _, ok := <-reader.ch:
		if ok {
			t.Fatal("the reader delivered data although segment 0 is missing")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reader is still waiting for a segment that will never arrive")
	}

	err = reader.Err()
	if err == nil || err == io.EOF {
		t.Fatalf("Err returned %v, want a failure about the missing segment", err)
	}
}

func TestReaderWaitsWhenNothingIsAhead(t *testing.T) {
	storage, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatalf("newLocalStorage: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := paramsFromConfig(&Config{PollIntervalMs: 5, MaxPollIntervalMs: 20, HoleTimeoutMs: 100})
	reader := newWALReader(ctx, storage, "idle", p)

	time.Sleep(400 * time.Millisecond)
	if err := storage.Put(ctx, segmentName("idle", 0), []byte("late")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	select {
	case data, ok := <-reader.ch:
		if !ok {
			t.Fatalf("the reader gave up on an idle stream: %v", reader.Err())
		}
		if string(data) != "late" {
			t.Fatalf("read %q, want %q", data, "late")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reader never picked up the late segment")
	}
}

func TestReaderStopsOnAFailureMarker(t *testing.T) {
	storage, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatalf("newLocalStorage: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := paramsFromConfig(&Config{PollIntervalMs: 5, MaxPollIntervalMs: 20})
	if err := storage.Put(ctx, segmentName("broken", 0), []byte("first")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := storage.Put(ctx, errName("broken", 1), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}

	reader := newWALReader(ctx, storage, "broken", p)

	select {
	case data, ok := <-reader.ch:
		if !ok || string(data) != "first" {
			t.Fatalf("the reader should have delivered the segment before the marker, got %q %v", data, ok)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reader never delivered the first segment")
	}

	select {
	case _, ok := <-reader.ch:
		if ok {
			t.Fatal("the reader kept delivering data past the failure marker")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reader is still waiting although the peer reported a failure")
	}

	if err := reader.Err(); err == nil || err == io.EOF {
		t.Fatalf("Err returned %v, want the peer's failure", err)
	}
}

type inlineOnlyStorage struct {
	Storage
	gets int64
}

func (s *inlineOnlyStorage) List(ctx context.Context, prefix string) ([]Entry, error) {
	return []Entry{{Name: "000000000" + segSuffix, Inline: []byte("carried by the listing")}}, nil
}

func (s *inlineOnlyStorage) Get(ctx context.Context, name string) ([]byte, error) {
	atomic.AddInt64(&s.gets, 1)
	return nil, errNotFound
}

func (s *inlineOnlyStorage) Delete(ctx context.Context, name string) error {
	return nil
}

func TestReaderPrefersInlinePayloads(t *testing.T) {
	base, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatalf("newLocalStorage: %v", err)
	}
	storage := &inlineOnlyStorage{Storage: base}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader := newWALReader(ctx, storage, "inline", paramsFromConfig(&Config{PollIntervalMs: 5}))
	select {
	case data, ok := <-reader.ch:
		if !ok {
			t.Fatalf("the reader stopped: %v", reader.Err())
		}
		if string(data) != "carried by the listing" {
			t.Fatalf("read %q, want the inline payload", data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reader never delivered the inline payload")
	}

	if got := atomic.LoadInt64(&storage.gets); got != 0 {
		t.Fatalf("the reader called Get %d times although the listing carried the payload", got)
	}
}
