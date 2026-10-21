package inbound

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/serial"
)

type testHandler struct {
	tag      string
	startErr error
	closed   bool
}

func (h *testHandler) Start() error {
	return h.startErr
}

func (h *testHandler) Close() error {
	h.closed = true
	return nil
}

func (h *testHandler) Tag() string {
	return h.tag
}

func (h *testHandler) ReceiverSettings() *serial.TypedMessage {
	return nil
}

func (h *testHandler) ProxySettings() *serial.TypedMessage {
	return nil
}

func TestAddHandlerFailedStart(t *testing.T) {
	ctx := context.Background()
	m, err := New(ctx, &proxyman.InboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}

	for _, tag := range []string{"in", ""} {
		failed := &testHandler{tag: tag, startErr: errors.New("address already in use")}
		if err := m.AddHandler(ctx, failed); err == nil {
			t.Fatalf("handler %q: expected the start error", tag)
		}
		if !failed.closed {
			t.Errorf("handler %q was not closed after failing to start", tag)
		}
		if n := len(m.ListHandlers(ctx)); n != 0 {
			t.Fatalf("handler %q is still registered after failing to start (%d handlers)", tag, n)
		}
	}

	if err := m.AddHandler(ctx, &testHandler{tag: "in"}); err != nil {
		t.Fatalf("cannot add the tag again: %v", err)
	}
}
