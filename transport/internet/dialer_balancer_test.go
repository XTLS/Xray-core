package internet

import (
	"context"
	stderrors "errors"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
)

type testOutboundManager struct {
	handlers map[string]outbound.Handler
	lookups  []string
}

func (*testOutboundManager) Start() error { return nil }

func (*testOutboundManager) Close() error { return nil }

func (*testOutboundManager) Type() interface{} { return outbound.ManagerType() }

func (m *testOutboundManager) GetHandler(tag string) outbound.Handler {
	m.lookups = append(m.lookups, tag)
	return m.handlers[tag]
}

func (m *testOutboundManager) GetDefaultHandler() outbound.Handler { return nil }

func (*testOutboundManager) AddHandler(context.Context, outbound.Handler) error { return nil }

func (*testOutboundManager) RemoveHandler(context.Context, string) error { return nil }

func (*testOutboundManager) ListHandlers(context.Context) []outbound.Handler { return nil }

type testOutboundHandler struct {
	tag string
}

func (h *testOutboundHandler) Start() error { return nil }

func (h *testOutboundHandler) Close() error { return nil }

func (h *testOutboundHandler) Tag() string { return h.tag }

func (*testOutboundHandler) Dispatch(context.Context, *transport.Link) {}

func (*testOutboundHandler) SenderSettings() *serial.TypedMessage { return nil }

func (*testOutboundHandler) ProxySettings() *serial.TypedMessage { return nil }

type testBalancerSelector struct {
	outboundTag string
	found       bool
	err         error
	calls       int
}

func (s *testBalancerSelector) PickBalancerOutbound(string) (string, bool, error) {
	s.calls++
	return s.outboundTag, s.found, s.err
}

func TestResolveDialerProxyUsesBalancerTag(t *testing.T) {
	handler := &testOutboundHandler{tag: "proxy"}
	manager := &testOutboundManager{
		handlers: map[string]outbound.Handler{
			"proxy": handler,
		},
	}
	selector := &testBalancerSelector{
		outboundTag: "proxy",
		found:       true,
	}

	prevObm := obm
	prevRoutingBalancer := routingBalancer
	obm = manager
	routingBalancer = selector
	t.Cleanup(func() {
		obm = prevObm
		routingBalancer = prevRoutingBalancer
	})

	tag, gotHandler, err := resolveDialerProxy(context.Background(), "balancer")
	if err != nil {
		t.Fatal(err)
	}
	if tag != "proxy" {
		t.Fatalf("unexpected outbound tag: got %q want %q", tag, "proxy")
	}
	if gotHandler != handler {
		t.Fatalf("unexpected outbound handler: got %v want %v", gotHandler, handler)
	}
	if selector.calls != 1 {
		t.Fatalf("unexpected balancer call count: got %d want %d", selector.calls, 1)
	}
	if diff := strings.Join(manager.lookups, ","); diff != "balancer,proxy" {
		t.Fatalf("unexpected lookup order: got %q want %q", diff, "balancer,proxy")
	}
}

func TestResolveDialerProxyReturnsBalancerError(t *testing.T) {
	manager := &testOutboundManager{}
	selector := &testBalancerSelector{
		found: true,
		err:   stderrors.New("no candidates"),
	}

	prevObm := obm
	prevRoutingBalancer := routingBalancer
	obm = manager
	routingBalancer = selector
	t.Cleanup(func() {
		obm = prevObm
		routingBalancer = prevRoutingBalancer
	})

	_, _, err := resolveDialerProxy(context.Background(), "balancer")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "failed to get outbound from dialerProxy balancer") {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff := strings.Join(manager.lookups, ","); diff != "balancer" {
		t.Fatalf("unexpected lookup order: got %q want %q", diff, "balancer")
	}
}
