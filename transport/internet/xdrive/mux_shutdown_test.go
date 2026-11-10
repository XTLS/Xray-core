package xdrive

import (
	"context"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	feature "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/vless"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

type vlessSlotDialer struct {
	feature.Handler
	conn *Conn
}

func (d vlessSlotDialer) SenderSettings() *serial.TypedMessage {
	return serial.ToTypedMessage(&proxyman.SenderConfig{
		MultiplexSettings: &proxyman.MultiplexingConfig{Enabled: true},
	})
}

func (d vlessSlotDialer) Dial(context.Context, net.Destination) (stat.Connection, error) {
	return &stat.CounterConnection{Connection: d.conn}, nil
}

func (vlessSlotDialer) DestIpAddress() net.IP                                 { return nil }
func (vlessSlotDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func muxSlotHandler(t *testing.T, conn *Conn) *vlessout.Handler {
	t.Helper()
	instance := new(core.Instance)
	if err := instance.AddFeature(policy.DefaultManager{}); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	ctx = context.WithValue(ctx, "cone", false)
	ctx = session.ContextWithFullHandler(ctx, vlessSlotDialer{conn: conn})
	id := uuid.New()
	handler, err := vlessout.New(ctx, &vlessout.Config{
		Vnext: &protocol.ServerEndpoint{
			Address: net.NewIPOrDomain(net.DomainAddress("vless.test")),
			Port:    443,
			User: &protocol.User{
				Account: serial.ToTypedMessage(&vless.Account{Id: id.String()}),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { handler.Close() })
	return handler
}

func muxSlotSession(t *testing.T, handler *vlessout.Handler, bytes int) (*pipe.Writer, *pipe.Reader) {
	t.Helper()
	input, client := pipe.New()
	output, reply := pipe.New()
	t.Cleanup(func() {
		client.Interrupt()
		reply.Interrupt()
	})
	mb := make(buf.MultiBuffer, 0, (bytes+buf.Size-1)/buf.Size)
	for bytes > 0 {
		b := buf.New()
		n := min(bytes, buf.Size)
		data := b.Extend(int32(n))
		clear(data)
		data[0] = 42
		mb = append(mb, b)
		bytes -= n
	}
	if err := client.WriteMultiBuffer(mb); err != nil {
		t.Fatal(err)
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("target.test"), 80),
	}})
	if handled, err := handler.DispatchMux(ctx, &transport.Link{Reader: input, Writer: reply}); !handled || err != nil {
		t.Fatalf("VLESS Mux admission: handled %v, error %v", handled, err)
	}
	return client, output
}

// Identify the selected writer goroutine, not a periodic XDrive flush.
func waitXDriveStack(t *testing.T, match func(string) bool) string {
	t.Helper()
	stack := make([]byte, 1<<20)
	for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
		text := string(stack[:runtime.Stack(stack, true)])
		for _, goroutine := range strings.Split(text, "\n\n") {
			if match(goroutine) {
				return strings.Fields(goroutine)[1]
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("XDrive writer did not reach the expected wait")
	return ""
}

func TestVlessMuxCloseUnblocksFullXDriveRing(t *testing.T) {
	store := newMemSlots()
	p := paramsFromConfig(&Config{Concurrency: 2, SegmentBytes: 2048})
	r, err := makeRing(context.Background(), store, "no-ack", p)
	if err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	conn := newSlotConn(context.Background(), store, r.Up, r.Down, p, nil, func() { close(released) })
	t.Cleanup(func() {
		conn.cancel() // Releases the negative control without waiting for the peer.
		conn.Close()
	})
	handler := muxSlotHandler(t, conn)
	_, output := muxSlotSession(t, handler, 256*1024)
	slots := conn.writer.(*slotWriter)
	writer := waitXDriveStack(t, func(stack string) bool {
		header, _, _ := strings.Cut(stack, "\n")
		if !strings.Contains(header, "[select") ||
			!strings.Contains(stack, "/common/mux.fetchInput(") ||
			!strings.Contains(stack, "/xdrive.(*slotWriter).flushLocked(") {
			return false
		}
		// First-lap uploads can still free a token. Wait for all tokens to
		// represent slots that cannot be reused without a peer watermark.
		slots.mu.Lock()
		full := slots.seq >= int64(len(r.Up.Slots)+cap(slots.slots)) && len(slots.slots) == cap(slots.slots)
		slots.mu.Unlock()
		return full
	})
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("full XDrive ring kept the VLESS carrier open after handler close")
	}
	if mb, err := output.ReadMultiBufferTimeout(time.Second); err != io.EOF {
		buf.ReleaseMulti(mb)
		t.Fatalf("logical session stayed open: %v", err)
	}
	stack := make([]byte, 1<<20)
	for until := time.Now().Add(time.Second); time.Now().Before(until); {
		text := string(stack[:runtime.Stack(stack, true)])
		if !strings.Contains(text, "\ngoroutine "+writer+" [") && len(slots.slots) == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("aborted XDrive carrier retained its writer or slot uploads")
}

func TestVlessMuxCloseSendsXDriveEOFWhenIdle(t *testing.T) {
	conn, peer := slotPair(t, newMemSlots(), 2, 2048)
	handler := muxSlotHandler(t, conn)
	input, output := muxSlotSession(t, handler, 1)
	if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Plain VLESS Mux has an empty addons header and no request address.
	var header [19]byte
	if _, err := io.ReadFull(peer, header[:]); err != nil || header[18] != byte(protocol.RequestCommandMux) {
		t.Fatalf("VLESS Mux request: %x, %v", header, err)
	}
	var frame mux.FrameMetadata
	if err := frame.Unmarshal(peer, false); err != nil || frame.SessionStatus != mux.SessionStatusNew {
		t.Fatalf("initial Mux frame: %+v, %v", frame, err)
	}
	var data [3]byte
	if _, err := io.ReadFull(peer, data[:]); err != nil || data != [3]byte{0, 1, 42} {
		t.Fatalf("Mux data: %x, %v", data, err)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	if mb, err := output.ReadMultiBufferTimeout(time.Second); err != io.EOF {
		buf.ReleaseMulti(mb)
		t.Fatalf("logical session stayed open: %v", err)
	}
	if err := frame.Unmarshal(peer, false); err != nil || frame.SessionStatus != mux.SessionStatusEnd {
		t.Fatalf("Mux session end: %+v, %v", frame, err)
	}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := peer.Read(data[:]); n != 0 || err != io.EOF {
		t.Fatalf("XDrive peer did not receive graceful EOF: %d, %v", n, err)
	}
}

func TestInterruptRejectsWriteWaitingForAdmission(t *testing.T) {
	for _, mode := range []string{"slot", "wal"} {
		t.Run(mode, func(t *testing.T) {
			p := paramsFromConfig(&Config{Concurrency: 2, SegmentBytes: 2048})
			var conn *Conn
			var lock *sync.Mutex
			if mode == "slot" {
				store := newMemSlots()
				r, err := makeRing(context.Background(), store, "admission", p)
				if err != nil {
					t.Fatal(err)
				}
				conn = newSlotConn(context.Background(), store, r.Up, r.Down, p, nil, nil)
				lock = &conn.writer.(*slotWriter).mu
			} else {
				store, err := newLocalStorage(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				conn = newConn(context.Background(), store, "up", "down", p, nil)
				lock = &conn.writer.(*walWriter).mu
			}
			defer conn.Interrupt()
			lock.Lock()
			locked := true
			defer func() {
				if locked {
					lock.Unlock()
				}
			}()
			type result struct {
				n   int
				err error
			}
			done := make(chan result, 1)
			go func() {
				n, err := conn.Write([]byte{42})
				done <- result{n, err}
			}()
			waitXDriveStack(t, func(stack string) bool {
				return strings.Contains(stack, "/xdrive.(*"+mode+"Writer).Write(") &&
					strings.Contains(stack, "sync.Mutex.Lock")
			})
			conn.Interrupt()
			lock.Unlock()
			locked = false
			select {
			case got := <-done:
				if got.n != 0 || got.err != io.ErrClosedPipe {
					t.Fatalf("canceled write admitted: %d bytes, %v", got.n, got.err)
				}
			case <-time.After(time.Second):
				t.Fatal("writer stayed blocked after interrupt")
			}
		})
	}
}

func TestInterruptedWALDoesNotScheduleBufferedWrite(t *testing.T) {
	store, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := paramsFromConfig(&Config{Concurrency: 1, SegmentBytes: 2048})
	p.flushInterval = time.Hour
	conn := newConn(context.Background(), store, "up", "down", p, nil)
	defer conn.Interrupt()
	if n, err := conn.Write([]byte{42}); n != 1 || err != nil {
		t.Fatalf("buffered write: %d, %v", n, err)
	}
	conn.Interrupt()
	writer := conn.writer.(*walWriter)
	writer.mu.Lock()
	err = writer.flushLocked()
	scheduled := writer.seq
	writer.mu.Unlock()
	if err != context.Canceled || scheduled != 0 {
		t.Fatalf("flush admitted after abort: %d segments, %v", scheduled, err)
	}
}

type pendingAnnounceStore struct {
	failPutStore
	started  chan struct{}
	canceled chan struct{}
	release  chan struct{}
}

func (s *pendingAnnounceStore) Put(ctx context.Context, _ string, _ []byte) error {
	close(s.started)
	select {
	case <-ctx.Done():
		close(s.canceled)
		return ctx.Err()
	case <-s.release:
		return nil
	}
}

func TestInterruptCancelsPendingXDriveAnnouncement(t *testing.T) {
	store := &pendingAnnounceStore{
		failPutStore: failPutStore{memSlots: newMemSlots()},
		started:      make(chan struct{}),
		canceled:     make(chan struct{}),
		release:      make(chan struct{}),
	}
	config := &Config{Service: "sim", RemoteFolder: t.TempDir(), Concurrency: 2}
	box := spareBoxFor(config)
	factory := func(*Config) (Storage, error) { return store, nil }
	testStorageFactory.Store(&factory)
	t.Cleanup(func() {
		close(store.release)
		box.stop.Store(true)
		for box.busy.Load() {
			time.Sleep(time.Millisecond)
		}
		testStorageFactory.Store(nil)
	})
	raw, err := Dial(context.Background(), net.Destination{}, &internet.MemoryStreamConfig{
		ProtocolName: protocolName, ProtocolSettings: config,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn := raw.(*Conn)
	defer conn.Interrupt()
	select {
	case <-store.started:
	case <-time.After(2 * time.Second):
		t.Fatal("XDrive did not start the announcement")
	}
	conn.Interrupt()
	select {
	case <-store.canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("XDrive announcement outlived the interrupted session")
	}
}
