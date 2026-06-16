package burst

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/tagged"
)

func TestPingClientReturnsErrorWhenTaggedDialerUnavailable(t *testing.T) {
	originalDialer := tagged.Dialer
	tagged.Dialer = nil
	t.Cleanup(func() {
		tagged.Dialer = originalDialer
	})

	client := newPingClient(
		context.Background(),
		noOpDispatcher{},
		"https://connectivitycheck.gstatic.com/generate_204",
		time.Second,
		"nl",
	)

	delay, err := client.MeasureDelay(http.MethodHead)
	if err == nil {
		t.Fatal("expected unavailable tagged dialer error")
	}
	if delay != rttFailed {
		t.Fatalf("expected rttFailed, got %s", delay)
	}
}

func TestPingClientReturnsErrorWhenDispatcherUnavailable(t *testing.T) {
	originalDialer := tagged.Dialer
	tagged.Dialer = func(context.Context, routing.Dispatcher, net.Destination, string) (net.Conn, error) {
		t.Fatal("dialer should not be called with nil dispatcher")
		return nil, nil
	}
	t.Cleanup(func() {
		tagged.Dialer = originalDialer
	})

	client := newPingClient(
		context.Background(),
		nil,
		"https://connectivitycheck.gstatic.com/generate_204",
		time.Second,
		"nl",
	)

	delay, err := client.MeasureDelay(http.MethodHead)
	if err == nil {
		t.Fatal("expected unavailable dispatcher error")
	}
	if delay != rttFailed {
		t.Fatalf("expected rttFailed, got %s", delay)
	}
}

type noOpDispatcher struct{}

func (noOpDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func (noOpDispatcher) Start() error {
	return nil
}

func (noOpDispatcher) Close() error {
	return nil
}

func (noOpDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, nil
}

func (noOpDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}
