package dispatcher

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// xrayKey matches the unexported key core uses to store its instance in
// contexts, so that tests can provide one.
const xrayKey core.XrayKey = 1

// recordingLogHandler captures the messages recorded by the package under
// test, so that deferred access log records can be asserted.
type recordingLogHandler struct {
	mu       sync.Mutex
	messages []log.Message
}

func (h *recordingLogHandler) Handle(msg log.Message) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.messages = append(h.messages, msg)
}

func (h *recordingLogHandler) accessMessage() *log.AccessMessage {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, m := range h.messages {
		if am, ok := m.(*log.AccessMessage); ok {
			return am
		}
	}
	return nil
}

func waitAccessMessage(t *testing.T, h *recordingLogHandler) *log.AccessMessage {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if m := h.accessMessage(); m != nil {
			return m
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for the access message")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

type fakeOutboundHandler struct {
	dispatch func(ctx context.Context, link *transport.Link)
}

func (h *fakeOutboundHandler) Tag() string { return "fake-out" }

func (h *fakeOutboundHandler) Dispatch(ctx context.Context, link *transport.Link) {
	h.dispatch(ctx, link)
}

func (h *fakeOutboundHandler) SenderSettings() *serial.TypedMessage { return nil }
func (h *fakeOutboundHandler) ProxySettings() *serial.TypedMessage  { return nil }
func (h *fakeOutboundHandler) Start() error                         { return nil }
func (h *fakeOutboundHandler) Close() error                         { return nil }

type fakeOutboundManager struct {
	handler outbound.Handler
}

func (m *fakeOutboundManager) Type() interface{} { return outbound.ManagerType() }

func (m *fakeOutboundManager) GetHandler(tag string) outbound.Handler { return m.handler }

func (m *fakeOutboundManager) GetDefaultHandler() outbound.Handler { return m.handler }

func (m *fakeOutboundManager) AddHandler(ctx context.Context, handler outbound.Handler) error {
	return nil
}

func (m *fakeOutboundManager) RemoveHandler(ctx context.Context, tag string) error { return nil }

func (m *fakeOutboundManager) ListHandlers(ctx context.Context) []outbound.Handler { return nil }

func (m *fakeOutboundManager) Start() error { return nil }

func (m *fakeOutboundManager) Close() error { return nil }

// userStatsPolicy enables the user uplink and downlink counters.
type userStatsPolicy struct{}

func (userStatsPolicy) Type() interface{} { return policy.ManagerType() }

func (userStatsPolicy) ForLevel(uint32) policy.Session {
	p := policy.SessionDefault()
	p.Stats.UserUplink = true
	p.Stats.UserDownlink = true
	return p
}

func (userStatsPolicy) ForSystem() policy.System { return policy.System{} }
func (userStatsPolicy) Start() error             { return nil }
func (userStatsPolicy) Close() error             { return nil }

// fakeStatsManager hands out per-name counters like app/stats does.
type fakeStatsManager struct {
	stats.NoopManager
	counters sync.Map
}

func (m *fakeStatsManager) GetOrRegisterCounter(name string) (stats.Counter, error) {
	if c, ok := m.counters.Load(name); ok {
		return c.(stats.Counter), nil
	}
	c, _ := m.counters.LoadOrStore(name, new(directionTraffic))
	return c.(stats.Counter), nil
}

func newTestDispatcher(t *testing.T, pm policy.Manager, sm stats.Manager, dispatch func(context.Context, *transport.Link)) *DefaultDispatcher {
	t.Helper()
	d := new(DefaultDispatcher)
	if err := d.Init(nil, &fakeOutboundManager{handler: &fakeOutboundHandler{dispatch: dispatch}}, routing.DefaultRouter{}, pm, sm); err != nil {
		t.Fatal(err)
	}
	return d
}

func testContext(email string) context.Context {
	ctx := context.Background()
	inbound := &session.Inbound{Tag: "test-in"}
	if email != "" {
		inbound.User = &protocol.MemoryUser{Email: email}
	}
	ctx = session.ContextWithInbound(ctx, inbound)
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   net.TCPDestination(net.LocalHostIP, 1234),
		To:     net.TCPDestination(net.DomainAddress("example.com"), 443),
		Status: log.AccessAccepted,
	})
	return ctx
}

func TestCounterFanout(t *testing.T) {
	a := new(directionTraffic)
	b := new(directionTraffic)
	f := fanoutCounter(nil, a, b)
	f.Add(3)
	f.Add(4)
	if a.Value() != 7 || b.Value() != 7 {
		t.Error("unexpected fanout values. want 7, but got ", a.Value(), " and ", b.Value())
	}
	if got := fanoutCounter().Value(); got != 0 {
		t.Error("unexpected empty fanout value. want 0, but got ", got)
	}
}

// TestDispatchLinkAccessTrafficDelayedCompensation verifies that the access
// record waits for a raw copy that reports its size after the outbound
// handler returned, like the splice fast path does on a cancelled connection.
func TestDispatchLinkAccessTrafficDelayedCompensation(t *testing.T) {
	const delayedDownlink = 777

	h := &recordingLogHandler{}
	log.RegisterHandler(h)

	copied := make(chan struct{})
	d := newTestDispatcher(t, policy.DefaultManager{}, stats.NoopManager{}, func(ctx context.Context, link *transport.Link) {
		// Like a raw copy on a cancelled connection: task.Run returns, and
		// with it the handler, while the copy is still running and accounts
		// its size only when it finishes.
		statWriter := link.Writer.(*SizeStatWriter)
		release := stats.Hold(statWriter.Counter)
		go func() {
			defer close(copied)
			defer release()
			statWriter.Counter.Add(delayedDownlink) // the splice compensation
		}()
	})

	uplinkReader, _ := pipe.New(pipe.WithoutSizeLimit())
	_, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())

	if err := d.DispatchLink(testContext(""), net.TCPDestination(net.DomainAddress("example.com"), 443), &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}); err != nil {
		t.Fatal(err)
	}

	// The copy finishes after DispatchLink has returned.
	<-copied

	m := waitAccessMessage(t, h)
	if m.Downlink != delayedDownlink {
		t.Error("unexpected downlink. want ", delayedDownlink, ", but got ", m.Downlink)
	}
}

// TestDispatchAccessTraffic verifies that the access log record of a
// dispatched connection is written after the connection ends, even if the
// outbound handler returns before that, like a mux client worker does.
func TestDispatchAccessTraffic(t *testing.T) {
	const (
		uplinkSize   = 1000
		downlinkSize = 600
	)

	h := &recordingLogHandler{}
	log.RegisterHandler(h)

	d := newTestDispatcher(t, policy.DefaultManager{}, stats.NoopManager{}, func(ctx context.Context, link *transport.Link) {
		// The handler returns immediately; the connection ends when the
		// background copy finishes and the link gets closed.
		go func() {
			buf.Copy(link.Reader, buf.Discard)
			if err := link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, downlinkSize))); err != nil {
				panic(err)
			}
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
		}()
	})

	link, err := d.Dispatch(testContext(""), net.TCPDestination(net.DomainAddress("example.com"), 443))
	if err != nil {
		t.Fatal(err)
	}

	if err := link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, uplinkSize))); err != nil {
		t.Fatal(err)
	}
	common.Close(link.Writer)

	if err := buf.Copy(link.Reader, buf.Discard); err != nil {
		t.Fatal(err)
	}

	m := waitAccessMessage(t, h)
	if m.Uplink != uplinkSize {
		t.Error("unexpected uplink. want ", uplinkSize, ", but got ", m.Uplink)
	}
	if m.Downlink != downlinkSize {
		t.Error("unexpected downlink. want ", downlinkSize, ", but got ", m.Downlink)
	}
	if m.Detour != "test-in >> fake-out" {
		t.Error("unexpected detour: ", m.Detour)
	}
}

// TestDispatchAccessTrafficWithUserStats verifies that the access log traffic
// and the user stats counters are fed once, without double counting, when both
// are enabled.
func TestDispatchAccessTrafficWithUserStats(t *testing.T) {
	const (
		uplinkSize   = 900
		downlinkSize = 400
	)
	const email = "user@example.com"

	h := &recordingLogHandler{}
	log.RegisterHandler(h)
	sm := new(fakeStatsManager)

	d := newTestDispatcher(t, userStatsPolicy{}, sm, func(ctx context.Context, link *transport.Link) {
		go func() {
			buf.Copy(link.Reader, buf.Discard)
			if err := link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, downlinkSize))); err != nil {
				panic(err)
			}
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
		}()
	})

	link, err := d.Dispatch(testContext(email), net.TCPDestination(net.DomainAddress("example.com"), 443))
	if err != nil {
		t.Fatal(err)
	}

	if err := link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, uplinkSize))); err != nil {
		t.Fatal(err)
	}
	common.Close(link.Writer)

	if err := buf.Copy(link.Reader, buf.Discard); err != nil {
		t.Fatal(err)
	}

	m := waitAccessMessage(t, h)
	if m.Uplink != uplinkSize || m.Downlink != downlinkSize {
		t.Error("unexpected traffic. want ", uplinkSize, "/", downlinkSize, ", but got ", m.Uplink, "/", m.Downlink)
	}

	uplink, _ := sm.GetOrRegisterCounter("user>>>" + email + ">>>traffic>>>uplink")
	downlink, _ := sm.GetOrRegisterCounter("user>>>" + email + ">>>traffic>>>downlink")
	if uplink.Value() != uplinkSize {
		t.Error("unexpected user uplink. want ", uplinkSize, ", but got ", uplink.Value())
	}
	if downlink.Value() != downlinkSize {
		t.Error("unexpected user downlink. want ", downlinkSize, ", but got ", downlink.Value())
	}
}

// TestDispatchLinkAccessTraffic verifies the counting on caller-provided
// links: the uplink is counted while being read by the outbound, the downlink
// while being written, and the record is written after the outbound returns.
func TestDispatchLinkAccessTraffic(t *testing.T) {
	const (
		uplinkSize   = 700
		downlinkSize = 300
	)

	h := &recordingLogHandler{}
	log.RegisterHandler(h)

	d := newTestDispatcher(t, policy.DefaultManager{}, stats.NoopManager{}, func(ctx context.Context, link *transport.Link) {
		buf.Copy(link.Reader, buf.Discard)
		if err := link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, downlinkSize))); err != nil {
			panic(err)
		}
		common.Close(link.Writer)
	})

	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
	if err := uplinkWriter.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, uplinkSize))); err != nil {
		t.Fatal(err)
	}
	common.Close(uplinkWriter)

	if err := d.DispatchLink(testContext(""), net.TCPDestination(net.DomainAddress("example.com"), 443), &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}); err != nil {
		t.Fatal(err)
	}

	if err := buf.Copy(downlinkReader, buf.Discard); err != nil {
		t.Fatal(err)
	}

	m := waitAccessMessage(t, h)
	if m.Uplink != uplinkSize {
		t.Error("unexpected uplink. want ", uplinkSize, ", but got ", m.Uplink)
	}
	if m.Downlink != downlinkSize {
		t.Error("unexpected downlink. want ", downlinkSize, ", but got ", m.Downlink)
	}
}

// TestDispatchLinkSniffingAccessTraffic verifies that the payload cached by
// the sniffer is not counted twice.
func TestDispatchLinkSniffingAccessTraffic(t *testing.T) {
	uplinkPayload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" + strings.Repeat("x", 500))
	downlinkSize := 128

	h := &recordingLogHandler{}
	log.RegisterHandler(h)

	d := newTestDispatcher(t, policy.DefaultManager{}, stats.NoopManager{}, func(ctx context.Context, link *transport.Link) {
		buf.Copy(link.Reader, buf.Discard)
		if err := link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, downlinkSize))); err != nil {
			panic(err)
		}
		common.Close(link.Writer)
	})

	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
	if err := uplinkWriter.WriteMultiBuffer(buf.MergeBytes(nil, uplinkPayload)); err != nil {
		t.Fatal(err)
	}
	common.Close(uplinkWriter)

	ctx := session.ContextWithContent(testContext(""), &session.Content{
		SniffingRequest: session.SniffingRequest{
			Enabled:                        true,
			OverrideDestinationForProtocol: []string{"http"},
		},
	})
	// The sniffer looks up the FakeDNS feature through the core instance in
	// the context, so an instance has to be present.
	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx = context.WithValue(ctx, xrayKey, instance)
	if err := d.DispatchLink(ctx, net.TCPDestination(net.DomainAddress("example.com"), 80), &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}); err != nil {
		t.Fatal(err)
	}

	if err := buf.Copy(downlinkReader, buf.Discard); err != nil {
		t.Fatal(err)
	}

	m := waitAccessMessage(t, h)
	if m.Uplink != int64(len(uplinkPayload)) {
		t.Error("unexpected uplink. want ", len(uplinkPayload), ", but got ", m.Uplink)
	}
	if m.Downlink != int64(downlinkSize) {
		t.Error("unexpected downlink. want ", downlinkSize, ", but got ", m.Downlink)
	}
}

// TestSpliceCompensationCounted verifies that bytes added by the splice fast
// path (proxy.CopyRawConnIfExist adds them to the SizeStatWriter counter after
// the raw copy finishes) are counted for the access log too.
func TestSpliceCompensationCounted(t *testing.T) {
	const (
		uplinkSize      = 100
		splicedDownlink = 555
	)

	h := &recordingLogHandler{}
	log.RegisterHandler(h)

	d := newTestDispatcher(t, policy.DefaultManager{}, stats.NoopManager{}, nil)

	ctx := testContext("")
	inbound, outbound, traffic := d.getLink(ctx)

	if err := inbound.Writer.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, uplinkSize))); err != nil {
		t.Fatal(err)
	}
	statWriter, ok := outbound.Writer.(*SizeStatWriter)
	if !ok {
		t.Fatal("outbound writer is not a SizeStatWriter")
	}
	statWriter.Counter.Add(splicedDownlink)

	traffic.deferredRecord(log.AccessMessageFromContext(ctx))
	common.Close(inbound.Writer)
	common.Close(outbound.Writer)

	m := waitAccessMessage(t, h)
	if m.Uplink != uplinkSize {
		t.Error("unexpected uplink. want ", uplinkSize, ", but got ", m.Uplink)
	}
	if m.Downlink != splicedDownlink {
		t.Error("unexpected downlink. want ", splicedDownlink, ", but got ", m.Downlink)
	}
}

func TestLinkAccessTrafficSettle(t *testing.T) {
	h := &recordingLogHandler{}
	log.RegisterHandler(h)

	traffic := newLinkAccessTraffic()
	traffic.settle()
	traffic.settle() // must be idempotent

	message := &log.AccessMessage{
		From:   net.TCPDestination(net.LocalHostIP, 1234),
		To:     net.TCPDestination(net.DomainAddress("example.com"), 443),
		Status: log.AccessAccepted,
		Email:  "original@example.com",
	}
	traffic.deferredRecord(message)
	// Changes to the message after arming must not alter the pending record.
	message.Email = "mutated@example.com"

	m := waitAccessMessage(t, h)
	if m.Uplink != 0 || m.Downlink != 0 {
		t.Error("unexpected traffic. want 0/0, but got ", m.Uplink, "/", m.Downlink)
	}
	// The record must be a frozen copy, not the message itself.
	if m == message {
		t.Error("recorded the message itself instead of a copy")
	}
	if m.Email != "original@example.com" {
		t.Error("the record was altered after arming, got email: ", m.Email)
	}
}

// blockingReader blocks its reads until released.
type blockingReader struct {
	release chan struct{}
	payload buf.MultiBuffer
}

func (r *blockingReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	<-r.release
	return r.payload, nil
}

// TestAccessTrafficWaitsForPendingRead verifies that the record is not
// written before the reads that are already running have accounted their
// bytes: a TimeoutWrapperReader read may only finish (and be counted) after
// the connection settled, for example on cancellation, when the upper layer
// returns before the copies are done.
func TestAccessTrafficWaitsForPendingRead(t *testing.T) {
	const payloadSize = 42

	h := &recordingLogHandler{}
	log.RegisterHandler(h)

	traffic := newLinkAccessTraffic()
	counter := fanoutCounter(traffic.uplink)

	reader := &blockingReader{
		release: make(chan struct{}),
		payload: buf.MergeBytes(nil, make([]byte, payloadSize)),
	}
	wrapper := &buf.TimeoutWrapperReader{Reader: reader, Counter: counter}

	// Start an asynchronous read that outlives the settle of the connection.
	wrapper.ReadMultiBufferTimeout(10 * time.Millisecond)

	traffic.deferredRecord(&log.AccessMessage{Status: log.AccessAccepted})
	traffic.settle() // like DispatchLink: the outbound handler returned

	// The pending read completes afterwards, like a copy on a cancelled
	// connection, and only then accounts its bytes.
	close(reader.release)

	m := waitAccessMessage(t, h)
	if m.Uplink != payloadSize {
		t.Error("unexpected uplink. want ", payloadSize, ", but got ", m.Uplink)
	}
}

func TestPipeAccessTraffic(t *testing.T) {
	h := &recordingLogHandler{}
	log.RegisterHandler(h)

	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())

	traffic := newPipeAccessTraffic(uplinkReader, downlinkReader)
	traffic.settle() // must be a no-op for pipe-based trackers

	// Count like getLink does: uplink on the inbound writer, downlink on the
	// outbound writer.
	inboundWriter := &SizeStatWriter{Counter: fanoutCounter(traffic.uplink), Writer: uplinkWriter}
	outboundWriter := &SizeStatWriter{Counter: fanoutCounter(traffic.downlink), Writer: downlinkWriter}

	if err := inboundWriter.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, 42))); err != nil {
		t.Fatal(err)
	}
	if err := outboundWriter.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, 24))); err != nil {
		t.Fatal(err)
	}
	traffic.deferredRecord(&log.AccessMessage{Status: log.AccessAccepted})
	common.Close(uplinkWriter)
	common.Close(downlinkWriter)

	m := waitAccessMessage(t, h)
	if m.Uplink != 42 || m.Downlink != 24 {
		t.Error("unexpected traffic. want 42/24, but got ", m.Uplink, "/", m.Downlink)
	}
}

// gatedReader returns its chunks in order, blocking before the last one until
// released, like a target connection that keeps delivering after the outbound
// handler returned. It signals started on its first read.
type gatedReader struct {
	release chan struct{}
	started chan struct{}
	chunks  []buf.MultiBuffer
}

func (r *gatedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if len(r.chunks) == 0 {
		return nil, io.EOF
	}
	if len(r.chunks) == 1 {
		// Block before the last chunk until the test releases the gate.
		<-r.release
	}
	mb := r.chunks[0]
	r.chunks = r.chunks[1:]
	if r.started != nil {
		close(r.started)
		r.started = nil
	}
	return mb, nil
}

// TestDispatchLinkWaitsForStragglerCopy verifies that the access record is
// not frozen while a copy of the connection can still account bytes: after
// task.Run returned early (cancellation or error), a straggler copy keeps
// running, and the bytes it transfers afterwards must be included in the
// record.
func TestDispatchLinkWaitsForStragglerCopy(t *testing.T) {
	const (
		firstChunk  = 100
		secondChunk = 200
	)

	h := &recordingLogHandler{}
	log.RegisterHandler(h)

	gate := make(chan struct{})
	started := make(chan struct{})
	copyDone := make(chan error, 1)
	d := newTestDispatcher(t, policy.DefaultManager{}, stats.NoopManager{}, func(ctx context.Context, link *transport.Link) {
		// Like task.Run returning on cancellation: the handler returns while
		// the copy is still running and keeps accounting afterwards.
		go func() {
			copyDone <- buf.Copy(&gatedReader{
				release: gate,
				started: started,
				chunks: []buf.MultiBuffer{
					buf.MergeBytes(nil, make([]byte, firstChunk)),
					buf.MergeBytes(nil, make([]byte, secondChunk)),
				},
			}, link.Writer)
		}()
		// Return only after the copy has started: buf.Copy holds the
		// endpoints' counters before its first read, so the settle happens
		// with the copy held, deterministically.
		<-started
	})

	uplinkReader, _ := pipe.New(pipe.WithoutSizeLimit())
	_, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())

	if err := d.DispatchLink(testContext(""), net.TCPDestination(net.DomainAddress("example.com"), 443), &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}); err != nil {
		t.Fatal(err)
	}

	// The copy is blocked mid-way and can still account bytes: no record
	// must be written in the meantime.
	deadline := time.After(300 * time.Millisecond)
	for {
		if m := h.accessMessage(); m != nil {
			t.Fatal("access record written while the copy can still account, got ", m.String())
		}
		select {
		case <-deadline:
		case <-time.After(20 * time.Millisecond):
			continue
		}
		break
	}

	// The copy finishes after DispatchLink has returned.
	close(gate)
	if err := <-copyDone; err != nil {
		t.Fatal(err)
	}

	m := waitAccessMessage(t, h)
	if m.Uplink != 0 {
		t.Error("unexpected uplink. want 0, but got ", m.Uplink)
	}
	if m.Downlink != firstChunk+secondChunk {
		t.Error("unexpected downlink. want ", firstChunk+secondChunk, ", but got ", m.Downlink)
	}
	if countAccessMessages(h) != 1 {
		t.Error("unexpected number of access records: ", countAccessMessages(h))
	}
}

// TestDirectionTrafficHoldAfterSettle covers the boundary: accounting that
// only starts after the direction settled is not waited for (transfers
// bracket themselves before they can outlive the connection), while the
// counter itself keeps updating.
func TestDirectionTrafficHoldAfterSettle(t *testing.T) {
	d := new(directionTraffic)
	d.Add(1)
	d.finish()

	release := d.Hold() // no-op after settling
	release()           // must be safe

	d.Add(4)
	if d.Value() != 5 {
		t.Error("unexpected value. want 5, but got ", d.Value())
	}
}

func countAccessMessages(h *recordingLogHandler) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, m := range h.messages {
		if _, ok := m.(*log.AccessMessage); ok {
			n++
		}
	}
	return n
}

type disabledAccessHandler struct{}

func (disabledAccessHandler) Handle(log.Message)  {}
func (disabledAccessHandler) AccessEnabled() bool { return false }

func TestDisabledAccessPreservesUserStats(t *testing.T) {
	log.RegisterHandler(disabledAccessHandler{})
	t.Cleanup(func() { log.RegisterHandler(&recordingLogHandler{}) })
	for _, userStats := range []bool{false, true} {
		name := "without-user-stats"
		if userStats {
			name = "with-user-stats"
		}
		t.Run(name, func(t *testing.T) {
			var pm policy.Manager = policy.DefaultManager{}
			if userStats {
				pm = userStatsPolicy{}
			}
			sm := &fakeStatsManager{}
			d := newTestDispatcher(t, pm, sm, func(ctx context.Context, link *transport.Link) {
				if accessTrafficFromContext(ctx) != nil {
					t.Error("disabled access logger allocated a traffic tracker")
				}
				reader := link.Reader.(*buf.TimeoutWrapperReader)
				if (reader.Counter != nil) != userStats {
					t.Error("unexpected uplink counter when access logging is disabled")
				}
				if _, ok := link.Writer.(*SizeStatWriter); ok != userStats {
					t.Error("unexpected downlink wrapper when access logging is disabled")
				}
				if err := buf.Copy(link.Reader, link.Writer); err != nil {
					t.Fatal(err)
				}
			})
			ctx := testContext("disabled@example.com")
			in, out, tracker := d.getLink(ctx)
			defer common.Close(in.Writer)
			defer common.Close(out.Writer)
			if tracker != nil {
				t.Fatal("disabled access logger allocated a pipe tracker")
			}
			if _, ok := in.Writer.(*SizeStatWriter); ok != userStats {
				t.Error("unexpected pipe uplink wrapper")
			}
			if _, ok := out.Writer.(*SizeStatWriter); ok != userStats {
				t.Error("unexpected pipe downlink wrapper")
			}
			link := &transport.Link{Reader: buf.NewReader(strings.NewReader("hello")), Writer: buf.Discard}
			if err := d.DispatchLink(ctx, net.TCPDestination(net.DomainAddress("example.com"), 443), link); err != nil {
				t.Fatal(err)
			}
			if userStats {
				for _, direction := range []string{"uplink", "downlink"} {
					counter, _ := sm.GetOrRegisterCounter("user>>>disabled@example.com>>>traffic>>>" + direction)
					if counter.Value() != 5 {
						t.Errorf("%s user counter = %d, want 5", direction, counter.Value())
					}
				}
			}
		})
	}
}

func TestNoAccessMessageSkipsTrafficTracker(t *testing.T) {
	log.RegisterHandler(&recordingLogHandler{})
	d := newTestDispatcher(t, policy.DefaultManager{}, stats.NoopManager{}, func(ctx context.Context, link *transport.Link) {
		if accessTrafficFromContext(ctx) != nil {
			t.Error("connection without an access message allocated a tracker")
		}
	})
	in, out, tracker := d.getLink(context.Background())
	defer common.Close(in.Writer)
	defer common.Close(out.Writer)
	if tracker != nil {
		t.Fatal("connection without an access message allocated a pipe tracker")
	}
	if err := d.DispatchLink(context.Background(), net.TCPDestination(net.DomainAddress("example.com"), 443), &transport.Link{
		Reader: buf.NewReader(strings.NewReader("")), Writer: buf.Discard,
	}); err != nil {
		t.Fatal(err)
	}
}

// blockingWriter reports its first write and blocks every write until
// released, like a downstream that keeps a copy running after its handler
// returned.
type blockingWriter struct {
	buf.Writer
	written chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.once.Do(func() { close(w.written) })
	<-w.release
	return w.Writer.WriteMultiBuffer(mb)
}

// TestDispatchLinkSniffingWaitsForStragglerCopy verifies that the sniffing
// cache does not hide the access log counting from the copies: with sniffing
// enabled, DispatchLink wraps the reader in a cachedReader, and a copy that
// is still running after the handler returned must still be waited for,
// including the bytes it accounts afterwards.
func TestDispatchLinkSniffingWaitsForStragglerCopy(t *testing.T) {
	const (
		firstChunk  = 100
		secondChunk = 200
	)

	h := &recordingLogHandler{}
	log.RegisterHandler(h)

	gate := make(chan struct{})
	written := make(chan struct{})
	copyDone := make(chan error, 1)
	d := newTestDispatcher(t, policy.DefaultManager{}, stats.NoopManager{}, func(ctx context.Context, link *transport.Link) {
		go func() {
			copyDone <- buf.Copy(link.Reader, &blockingWriter{Writer: buf.Discard, written: written, release: gate})
		}()
		// Return only after the copy started and blocked in its first write:
		// the read of the first chunk is over by then, so only the copy-level
		// hold can keep the record waiting for the remaining bytes.
		<-written
	})

	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	_, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
	if err := uplinkWriter.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, firstChunk))); err != nil {
		t.Fatal(err)
	}

	ctx := session.ContextWithContent(testContext(""), &session.Content{
		SniffingRequest: session.SniffingRequest{
			Enabled:      true,
			MetadataOnly: true,
		},
	})
	// The sniffer looks up the FakeDNS feature through the core instance in
	// the context, so an instance has to be present.
	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx = context.WithValue(ctx, xrayKey, instance)
	if err := d.DispatchLink(ctx, net.TCPDestination(net.DomainAddress("example.com"), 443), &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}); err != nil {
		t.Fatal(err)
	}

	// The copy is blocked in its first write and can still account bytes: no
	// record must be written in the meantime.
	deadline := time.After(300 * time.Millisecond)
	for {
		if m := h.accessMessage(); m != nil {
			t.Fatal("access record written while the copy can still account, got ", m.String())
		}
		select {
		case <-deadline:
		case <-time.After(20 * time.Millisecond):
			continue
		}
		break
	}

	// The remaining uplink arrives after DispatchLink has returned.
	if err := uplinkWriter.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, secondChunk))); err != nil {
		t.Fatal(err)
	}
	common.Close(uplinkWriter)
	close(gate)
	if err := <-copyDone; err != nil {
		t.Fatal(err)
	}

	m := waitAccessMessage(t, h)
	if m.Uplink != firstChunk+secondChunk {
		t.Error("unexpected uplink. want ", firstChunk+secondChunk, ", but got ", m.Uplink)
	}
	if m.Downlink != 0 {
		t.Error("unexpected downlink. want 0, but got ", m.Downlink)
	}
	if countAccessMessages(h) != 1 {
		t.Error("unexpected number of access records: ", countAccessMessages(h))
	}
}
