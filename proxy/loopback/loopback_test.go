package loopback

import (
	"context"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type recordingDispatcher struct {
	ctx   context.Context
	calls int
}

func (*recordingDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func (*recordingDispatcher) Start() error {
	return nil
}

func (*recordingDispatcher) Close() error {
	return nil
}

func (*recordingDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, nil
}

func (d *recordingDispatcher) DispatchLink(ctx context.Context, _ net.Destination, _ *transport.Link) error {
	d.ctx = ctx
	d.calls++
	return nil
}

func newTestLink() *transport.Link {
	return &transport.Link{
		Reader: buf.NewReader(strings.NewReader("")),
		Writer: buf.Discard,
	}
}

func TestLoopbackRejectsRepeatedInboundTag(t *testing.T) {
	defaultDispatcher := new(recordingDispatcher)
	standbyDispatcher := new(recordingDispatcher)
	defaultLoopback := &Loopback{
		inboundTag:         "loopback-default",
		dispatcherInstance: defaultDispatcher,
	}
	standbyLoopback := &Loopback{
		inboundTag:         "loopback-standby",
		dispatcherInstance: standbyDispatcher,
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 443),
	}})

	if err := defaultLoopback.Process(ctx, newTestLink(), nil); err != nil {
		t.Fatalf("unexpected first loopback error: %v", err)
	}
	if defaultDispatcher.calls != 1 {
		t.Fatalf("expected first loopback to dispatch once, got %d", defaultDispatcher.calls)
	}

	if err := standbyLoopback.Process(defaultDispatcher.ctx, newTestLink(), nil); err != nil {
		t.Fatalf("unexpected different loopback error: %v", err)
	}
	if standbyDispatcher.calls != 1 {
		t.Fatalf("expected different loopback to dispatch once, got %d", standbyDispatcher.calls)
	}

	if err := defaultLoopback.Process(standbyDispatcher.ctx, newTestLink(), nil); err == nil {
		t.Fatal("expected repeated loopback inbound tag to be rejected")
	}
	if defaultDispatcher.calls != 1 {
		t.Fatalf("expected repeated loopback to be rejected before dispatch, got %d calls", defaultDispatcher.calls)
	}
}
