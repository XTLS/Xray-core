package outbound

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	stdnet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

type lifecycleHandler struct {
	tag       string
	closeCall atomic.Int32
	onClose   func() error
}

func (h *lifecycleHandler) Tag() string                               { return h.tag }
func (h *lifecycleHandler) Start() error                              { return nil }
func (h *lifecycleHandler) Dispatch(context.Context, *transport.Link) {}
func (h *lifecycleHandler) SenderSettings() *serial.TypedMessage      { return nil }
func (h *lifecycleHandler) ProxySettings() *serial.TypedMessage       { return nil }
func (h *lifecycleHandler) Close() error {
	h.closeCall.Add(1)
	if h.onClose != nil {
		return h.onClose()
	}
	return nil
}

func lifecycleManager(t *testing.T) *Manager {
	t.Helper()
	m, err := New(context.Background(), &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRemoveHandlerClosesAndUnregisters(t *testing.T) {
	m := lifecycleManager(t)
	h := &lifecycleHandler{tag: "pingBatch-node"}
	if err := m.AddHandler(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if got := m.Select([]string{"pingBatch-"}); len(got) != 1 {
		t.Fatalf("initial selection = %v", got)
	}
	if err := m.RemoveHandler(context.Background(), h.tag); err != nil {
		t.Fatal(err)
	}
	if got := h.closeCall.Load(); got != 1 {
		t.Errorf("removed handler Close calls = %d, want 1", got)
	}
	if m.GetHandler(h.tag) != nil || m.GetDefaultHandler() != nil {
		t.Error("removed handler is still registered")
	}
	if got := m.Select([]string{"pingBatch-"}); len(got) != 0 {
		t.Errorf("selection after removal = %v", got)
	}
	if err := m.RemoveHandler(context.Background(), h.tag); err != nil {
		t.Fatal(err)
	}
	if got := h.closeCall.Load(); got != 1 {
		t.Errorf("unknown-tag removal closed handler again: %d", got)
	}
}

func TestRemoveHandlerCloseError(t *testing.T) {
	m := lifecycleManager(t)
	want := stderrors.New("handler close failed")
	h := &lifecycleHandler{tag: "pingBatch-error", onClose: func() error { return want }}
	if err := m.AddHandler(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveHandler(context.Background(), h.tag); !stderrors.Is(err, want) {
		t.Errorf("RemoveHandler error = %v, want %v", err, want)
	}
	if m.GetHandler(h.tag) != nil {
		t.Error("close error left handler registered")
	}
}

func TestRemoveHandlerCloseMayReplaceTag(t *testing.T) {
	m := lifecycleManager(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	old := &lifecycleHandler{tag: "pingBatch-same", onClose: func() error {
		close(entered)
		<-release
		return nil
	}}
	if err := m.AddHandler(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- m.RemoveHandler(context.Background(), old.tag) }()
	defer releaseOnce.Do(func() { close(release) })
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("RemoveHandler returned before closing old handler: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("RemoveHandler did not call old handler Close")
	}
	replacement := &lifecycleHandler{tag: old.tag}
	added := make(chan error, 1)
	go func() {
		if m.GetHandler(old.tag) != nil {
			added <- stderrors.New("old handler still registered during Close")
			return
		}
		added <- m.AddHandler(context.Background(), replacement)
	}()
	select {
	case err := <-added:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler Close holds manager lock")
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if m.GetHandler(old.tag) != replacement || replacement.closeCall.Load() != 0 {
		t.Error("closing old handler affected replacement with the same tag")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestManagerCloseClearsHandlersBeforeCallbacks(t *testing.T) {
	m := lifecycleManager(t)
	seen := make(chan bool, 1)
	h := &lifecycleHandler{tag: "pingBatch-close", onClose: func() error {
		seen <- m.GetDefaultHandler() == nil && m.GetHandler("pingBatch-close") == nil && len(m.ListHandlers(context.Background())) == 0 && len(m.Select([]string{"pingBatch-"})) == 0
		return nil
	}}
	untagged := &lifecycleHandler{}
	if err := m.AddHandler(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if err := m.AddHandler(context.Background(), untagged); err != nil {
		t.Fatal(err)
	}
	m.Select([]string{"pingBatch-"})
	done := make(chan error, 1)
	go func() { done <- m.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("manager Close holds lock while calling handler Close")
	}
	if !<-seen {
		t.Error("handler ownership was not cleared before Close callback")
	}
	if h.closeCall.Load() != 1 || untagged.closeCall.Load() != 1 {
		t.Error("manager did not close all tagged and untagged handlers")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if h.closeCall.Load() != 1 || untagged.closeCall.Load() != 1 {
		t.Error("second manager Close closed handlers again")
	}
}

type lifecycleProxy struct {
	closeCall   atomic.Int32
	processCall atomic.Int32
	closeErr    error
}

func (p *lifecycleProxy) Process(context.Context, *transport.Link, internet.Dialer) error {
	p.processCall.Add(1)
	return nil
}

func (p *lifecycleProxy) Close() error {
	p.closeCall.Add(1)
	return p.closeErr
}

var handlerCloseProtocolID atomic.Uint64

func TestHandlerCloseOwnsStreamConfigAndRetainsErrors(t *testing.T) {
	protocol := fmt.Sprintf("handler-close-test-%d", handlerCloseProtocolID.Add(1))
	streamErr := stderrors.New("stream cleanup failed")
	proxyErr := stderrors.New("proxy cleanup failed")
	var calls atomic.Int32
	config := &internet.MemoryStreamConfig{ProtocolName: protocol}
	if err := internet.RegisterTransportCloser(protocol, func(s *internet.MemoryStreamConfig) error {
		if s != config || !s.IsClosed() {
			t.Error("handler cleanup did not close the owned stream config")
		}
		calls.Add(1)
		return streamErr
	}); err != nil {
		t.Fatal(err)
	}
	p := &lifecycleProxy{closeErr: proxyErr}
	h := &Handler{streamSettings: config, proxy: p}
	for i := 0; i < 2; i++ {
		err := h.Close()
		if !stderrors.Is(err, streamErr) || !stderrors.Is(err, proxyErr) {
			t.Errorf("Close error = %v, want stream and proxy errors", err)
		}
	}
	if calls.Load() != 1 || p.closeCall.Load() != 1 {
		t.Error("repeat Close repeated cleanup")
	}
}

func TestClosedHandlerRejectsStartDialAndDispatch(t *testing.T) {
	p := &lifecycleProxy{}
	h := &Handler{proxy: p}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.Start(); !stderrors.Is(err, stdnet.ErrClosed) {
		t.Errorf("closed Start error = %v", err)
	}
	if conn, err := h.Dial(context.Background(), net.TCPDestination(net.ParseAddress("127.0.0.1"), 80)); conn != nil || !stderrors.Is(err, stdnet.ErrClosed) {
		t.Errorf("closed Dial = (%v, %v)", conn, err)
	}
	inputReader, inputWriter := pipe.New()
	outputReader, outputWriter := pipe.New()
	defer inputWriter.Close()
	defer outputWriter.Close()
	h.Dispatch(context.Background(), &transport.Link{Reader: inputReader, Writer: outputWriter})
	if _, err := inputReader.ReadMultiBufferTimeout(100 * time.Millisecond); !stderrors.Is(err, io.ErrClosedPipe) {
		t.Errorf("closed Dispatch input error = %v", err)
	}
	if _, err := outputReader.ReadMultiBufferTimeout(100 * time.Millisecond); !stderrors.Is(err, io.ErrClosedPipe) {
		t.Errorf("closed Dispatch output error = %v", err)
	}
	if p.processCall.Load() != 0 {
		t.Error("closed Dispatch reached proxy")
	}
}

func TestConcurrentSelectAndHandlerRemoval(t *testing.T) {
	m := lifecycleManager(t)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				m.Select([]string{"pingBatch-"})
			}
		}()
	}
	for i := 0; i < 200; i++ {
		h := &lifecycleHandler{tag: "pingBatch-selector"}
		if err := m.AddHandler(context.Background(), h); err != nil {
			t.Fatal(err)
		}
		if err := m.RemoveHandler(context.Background(), h.tag); err != nil {
			t.Fatal(err)
		}
		if h.closeCall.Load() != 1 {
			t.Fatal("removed selector handler was not closed")
		}
	}
	wg.Wait()
	if tags := m.Select([]string{"pingBatch-"}); len(tags) != 0 {
		t.Errorf("selector retained removed handlers: %v", tags)
	}
}

func TestHandlerCloseOnce(t *testing.T) {
	p := &lifecycleProxy{}
	h := &Handler{proxy: p}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := h.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := p.closeCall.Load(); got != 1 {
		t.Errorf("concurrent Close calls reached proxy %d times, want 1", got)
	}
}
