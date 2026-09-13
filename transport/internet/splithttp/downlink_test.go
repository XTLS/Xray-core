package splithttp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/signal/done"
)

type failingWriter struct {
	http.ResponseWriter
	fail bool
}

func (w *failingWriter) Write(b []byte) (int, error) {
	if w.fail {
		return 0, errors.New("stream reset")
	}
	return w.ResponseWriter.Write(b)
}

func (w *failingWriter) Flush() {}

func newTestConn(rw http.ResponseWriter) *httpServerConn {
	return &httpServerConn{Instance: done.New(), ResponseWriter: rw}
}

func TestDownlinkReplaysFromOffset(t *testing.T) {
	d := newDownlinkBuffer(1024)
	first := httptest.NewRecorder()
	if err := d.Attach(newTestConn(first), 0); err != nil {
		t.Fatal(err)
	}
	d.Write([]byte("hello world"))

	second := httptest.NewRecorder()
	if err := d.Attach(newTestConn(second), 5); err != nil {
		t.Fatal(err)
	}
	if got := second.Body.String(); got != " world" {
		t.Fatalf("replayed %q, want %q", got, " world")
	}
}

func TestDownlinkRejectsOffsetOutsideWindow(t *testing.T) {
	d := newDownlinkBuffer(1024)
	if err := d.Attach(newTestConn(httptest.NewRecorder()), 0); err != nil {
		t.Fatal(err)
	}
	d.Write([]byte("0123456789"))
	d.Ack(6)

	if err := d.CanAttach(3); err == nil {
		t.Fatal("expected a trimmed offset to be rejected")
	}
	if err := d.CanAttach(99); err == nil {
		t.Fatal("expected an offset ahead of sent to be rejected")
	}
	if err := d.CanAttach(8); err != nil {
		t.Fatalf("offset inside the window rejected: %v", err)
	}
}

func TestDownlinkTrimsOldestWhenFull(t *testing.T) {
	d := newDownlinkBuffer(8)
	if err := d.Attach(newTestConn(httptest.NewRecorder()), 0); err != nil {
		t.Fatal(err)
	}
	d.Write([]byte("0123456789ab"))

	if err := d.CanAttach(12); err != nil {
		t.Fatalf("the newest offset must stay servable: %v", err)
	}
	if err := d.CanAttach(0); err == nil {
		t.Fatal("expected the trimmed start to be rejected")
	}
}

// A stream reset must not surface to the tunnel: the bytes stay retained.
func TestDownlinkWriteSurvivesFailingStream(t *testing.T) {
	d := newDownlinkBuffer(1024)
	failing := &failingWriter{ResponseWriter: httptest.NewRecorder(), fail: true}
	if err := d.Attach(newTestConn(failing), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Write([]byte("payload")); err != nil {
		t.Fatalf("Write reported a dead stream to the tunnel: %v", err)
	}

	next := httptest.NewRecorder()
	if err := d.Attach(newTestConn(next), 0); err != nil {
		t.Fatal(err)
	}
	if got := next.Body.String(); got != "payload" {
		t.Fatalf("replayed %q after the reset, want %q", got, "payload")
	}
}

func TestDownlinkBuffersWhileDetached(t *testing.T) {
	d := newDownlinkBuffer(1024)
	d.Write([]byte("early"))

	rec := httptest.NewRecorder()
	if err := d.Attach(newTestConn(rec), 0); err != nil {
		t.Fatal(err)
	}
	if got := rec.Body.String(); got != "early" {
		t.Fatalf("replayed %q, want %q", got, "early")
	}
}

// Trimming must not leave the backing array growing with the stream.
func TestDownlinkRetentionStaysBounded(t *testing.T) {
	const window int32 = 64 << 10
	d := newDownlinkBuffer(window)
	if err := d.Attach(newTestConn(httptest.NewRecorder()), 0); err != nil {
		t.Fatal(err)
	}

	chunk := make([]byte, 4<<10)
	for i := 0; i < 4096; i++ {
		d.Write(chunk)
		if i%8 == 0 {
			d.Ack(d.sent)
		}
	}

	d.access.Lock()
	defer d.access.Unlock()
	if d.buf.Len() > window {
		t.Fatalf("retained %d bytes for a %d byte window", d.buf.Len(), window)
	}
}

// A closed buffer must still hand out what the client has not received yet,
// and report the final length.
func TestDownlinkFinishedKeepsRetainedBytes(t *testing.T) {
	d := newDownlinkBuffer(1024)
	if err := d.Attach(newTestConn(httptest.NewRecorder()), 0); err != nil {
		t.Fatal(err)
	}
	d.Write([]byte("tail bytes"))
	d.Close()

	done, sent := d.Finished()
	if !done || sent != 10 {
		t.Fatalf("Finished() = %v, %d, want true, 10", done, sent)
	}
	rec := httptest.NewRecorder()
	if err := d.Attach(newTestConn(rec), 4); err != nil {
		t.Fatalf("a finished buffer refused a retained offset: %v", err)
	}
	if got := rec.Body.String(); got != " bytes" {
		t.Fatalf("replayed %q, want %q", got, " bytes")
	}
}

// Back-pressure while detached must be released by Close, not deadlock.
func TestDownlinkCloseUnblocksWrite(t *testing.T) {
	d := newDownlinkBuffer(4)
	blocked := make(chan struct{})
	go func() {
		d.Write([]byte("aaaa"))
		d.Write([]byte("bbbb"))
		close(blocked)
	}()

	select {
	case <-blocked:
		t.Fatal("Write should have blocked at the retention cap while detached")
	case <-time.After(100 * time.Millisecond):
	}

	d.Close()
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("Close did not release a blocked Write")
	}
}

func TestDownlinkConcurrentAttachDetachWrite(t *testing.T) {
	d := newDownlinkBuffer(64 << 10)
	if err := d.Attach(newTestConn(httptest.NewRecorder()), 0); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	time.AfterFunc(2*time.Second, func() { close(stop) })
	wg.Add(3)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				d.Write([]byte("0123456789"))
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				conn := newTestConn(httptest.NewRecorder())
				d.access.Lock()
				offset := d.sent
				d.access.Unlock()
				if err := d.Attach(conn, offset); err == nil {
					d.Detach(conn)
				}
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				d.access.Lock()
				sent := d.sent
				d.access.Unlock()
				d.Ack(sent)
			}
		}
	}()

	// Production always reaches Close through the session grace timer; a Write
	// parked on back-pressure must be released by it.
	time.AfterFunc(2100*time.Millisecond, func() { d.Close() })

	waited := make(chan struct{})
	go func() { wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent attach/detach/write deadlocked")
	}
}
