package masque

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet/splithttp"
)

func newTestClient(newConn func(c *Client) splithttp.XmuxConn) *Client {
	c := &Client{ctx: context.Background()}
	c.xmux = splithttp.NewXmuxManager(splithttp.XmuxConfig{
		MaxConnections: &splithttp.RangeConfig{From: 3, To: 3},
	}, func() splithttp.XmuxConn {
		return newConn(c)
	})
	return c
}

func TestGetTunnelFallsBack(t *testing.T) {
	refused := errors.New("refused")
	healthy := &tunnel{done: make(chan struct{})}
	dials := 0
	c := newTestClient(func(c *Client) splithttp.XmuxConn {
		if dials++; dials == 1 {
			return healthy
		}
		c.lastErr, c.lastErrAt = refused, time.Now()
		return failedTunnel(refused)
	})
	for i := 0; i < 5; i++ {
		if _, got, err := c.getTunnel(context.Background(), nil); err != nil || got != healthy {
			t.Fatalf("flow %d: got %p, %v instead of the healthy tunnel", i, got, err)
		}
	}
	if dials != 2 {
		t.Errorf("dialed %d times, a failed tunnel should not be retried within %v", dials, retryInterval)
	}
}

func TestGetTunnelFailsWithoutTunnels(t *testing.T) {
	refused := errors.New("refused")
	c := newTestClient(func(c *Client) splithttp.XmuxConn {
		c.lastErr, c.lastErrAt = refused, time.Now()
		return failedTunnel(refused)
	})
	for i := 0; i < 2; i++ {
		if _, _, err := c.getTunnel(context.Background(), nil); err != refused {
			t.Fatalf("flow %d: got %v instead of %v", i, err, refused)
		}
	}
}
