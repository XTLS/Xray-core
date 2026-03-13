package splithttp_test

import (
	"context"
	"testing"

	. "github.com/xtls/xray-core/transport/internet/splithttp"
)

type fakeRoundTripper struct {
	closed bool
}

func (f *fakeRoundTripper) IsClosed() bool {
	return f.closed
}

func TestMaxConnections(t *testing.T) {
	xmuxConfig := XmuxConfig{
		MaxConnections: &RangeConfig{From: 4, To: 4},
	}

	xmuxManager := NewXmuxManager(xmuxConfig, func() XmuxConn {
		return &fakeRoundTripper{}
	})

	xmuxClients := make(map[interface{}]struct{})
	for i := 0; i < 8; i++ {
		xmuxClients[xmuxManager.GetXmuxClient(context.Background())] = struct{}{}
	}

	if len(xmuxClients) != 4 {
		t.Error("did not get 4 distinct clients, got ", len(xmuxClients))
	}
}

func TestCMaxReuseTimes(t *testing.T) {
	xmuxConfig := XmuxConfig{
		CMaxReuseTimes: &RangeConfig{From: 2, To: 2},
	}

	xmuxManager := NewXmuxManager(xmuxConfig, func() XmuxConn {
		return &fakeRoundTripper{}
	})

	xmuxClients := make(map[interface{}]struct{})
	for i := 0; i < 64; i++ {
		xmuxClients[xmuxManager.GetXmuxClient(context.Background())] = struct{}{}
	}

	if len(xmuxClients) != 32 {
		t.Error("did not get 32 distinct clients, got ", len(xmuxClients))
	}
}

func TestMaxConcurrency(t *testing.T) {
	xmuxConfig := XmuxConfig{
		MaxConcurrency: &RangeConfig{From: 2, To: 2},
	}

	xmuxManager := NewXmuxManager(xmuxConfig, func() XmuxConn {
		return &fakeRoundTripper{}
	})

	xmuxClients := make(map[interface{}]struct{})
	for i := 0; i < 64; i++ {
		xmuxClient := xmuxManager.GetXmuxClient(context.Background())
		xmuxClient.OpenUsage.Add(1)
		xmuxClients[xmuxClient] = struct{}{}
	}

	if len(xmuxClients) != 32 {
		t.Error("did not get 32 distinct clients, got ", len(xmuxClients))
	}
}

func TestDefault(t *testing.T) {
	xmuxConfig := XmuxConfig{}

	xmuxManager := NewXmuxManager(xmuxConfig, func() XmuxConn {
		return &fakeRoundTripper{}
	})

	xmuxClients := make(map[interface{}]struct{})
	for i := 0; i < 64; i++ {
		xmuxClient := xmuxManager.GetXmuxClient(context.Background())
		xmuxClient.OpenUsage.Add(1)
		xmuxClients[xmuxClient] = struct{}{}
	}

	if len(xmuxClients) != 1 {
		t.Error("did not get 1 distinct clients, got ", len(xmuxClients))
	}
}

func TestIsAllDead_AllClosed(t *testing.T) {
	rt := &fakeRoundTripper{}
	xmuxManager := NewXmuxManager(XmuxConfig{}, func() XmuxConn {
		return rt
	})

	client := xmuxManager.GetXmuxClient(context.Background())
	client.OpenUsage.Add(1)

	if xmuxManager.IsAllDead() {
		t.Error("expected manager to be alive while client has open usage")
	}

	client.OpenUsage.Add(-1)
	rt.closed = true

	if !xmuxManager.IsAllDead() {
		t.Error("expected manager to be dead after all clients closed")
	}
}

func TestIsAllDead_EmptyManager(t *testing.T) {
	xmuxManager := NewXmuxManager(XmuxConfig{}, func() XmuxConn {
		return &fakeRoundTripper{}
	})

	// Empty manager (no clients ever created) should not be considered dead
	if xmuxManager.IsAllDead() {
		t.Error("empty manager should not be considered dead")
	}
}
