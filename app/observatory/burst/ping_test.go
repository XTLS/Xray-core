package burst

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v2net "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tagged"
)

func TestPingClientDeadlineCancelsTaggedDial(t *testing.T) {
	type pingContextKey struct{}
	contextValue := new(int)
	originalDialer := tagged.Dialer
	defer func() { tagged.Dialer = originalDialer }()

	dialStarted := make(chan struct{})
	dialCanceled := make(chan struct{})
	var startOnce sync.Once
	var cancelOnce sync.Once
	var retainedContextValue atomic.Bool
	tagged.Dialer = func(ctx context.Context, _ routing.Dispatcher, _ v2net.Destination, _ string) (v2net.Conn, error) {
		if ctx.Value(pingContextKey{}) == contextValue {
			retainedContextValue.Store(true)
		}
		startOnce.Do(func() { close(dialStarted) })
		<-ctx.Done()
		cancelOnce.Do(func() { close(dialCanceled) })
		return nil, ctx.Err()
	}

	client := newPingClient(
		context.WithValue(context.Background(), pingContextKey{}, contextValue),
		nil,
		"http://probe.invalid/",
		20*time.Millisecond,
		"proxy-a",
	)
	if _, err := client.MeasureDelay(http.MethodHead); err == nil {
		t.Fatal("probe unexpectedly succeeded")
	}

	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("tagged dial did not start")
	}
	select {
	case <-dialCanceled:
	case <-time.After(time.Second):
		t.Fatal("probe deadline did not cancel the tagged dial")
	}
	if !retainedContextValue.Load() {
		t.Fatal("tagged dial did not retain the observer context values")
	}
}
