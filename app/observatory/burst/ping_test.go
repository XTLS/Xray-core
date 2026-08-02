package burst

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tagged"
)

// doCheck must hand its own context to the probes it starts, so that
// canceling a round also cancels the dials that round created.
func TestDoCheckPassesRoundContextToProbes(t *testing.T) {
	originalDialer := tagged.Dialer
	defer func() { tagged.Dialer = originalDialer }()

	instance := new(core.Instance)
	instanceCtx := context.WithValue(context.Background(), core.XrayKey(1), instance)

	dialed := make(chan context.Context, 1)
	tagged.Dialer = func(ctx context.Context, _ routing.Dispatcher, _ net.Destination, _ string) (net.Conn, error) {
		select {
		case dialed <- ctx:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}

	h := NewHealthPing(instanceCtx, nil, &HealthPingConfig{
		Destination: "http://example.com",
		Timeout:     int64(time.Minute),
	})

	roundCtx, cancelRound := context.WithCancel(h.ctx)
	go h.doCheck(roundCtx, []string{"probe"}, 0, 1)

	var dialCtx context.Context
	select {
	case dialCtx = <-dialed:
	case <-time.After(5 * time.Second):
		t.Fatal("probe never dialed")
	}

	if core.FromContext(dialCtx) != instance {
		t.Fatal("dial context lost the Xray instance")
	}

	cancelRound()

	select {
	case <-dialCtx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("canceling the round did not cancel the probe dial")
	}
}
