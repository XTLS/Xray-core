package outbound

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
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
	closeCall atomic.Int32
	closeErr  error
}

func (p *lifecycleProxy) Process(context.Context, *transport.Link, internet.Dialer) error {
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
