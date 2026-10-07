package finalmask

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

func TestResolverDialPreservesCallerContext(t *testing.T) {
	type contextKey struct{}
	outer := context.WithValue(context.Background(), contextKey{}, "routing metadata")
	inner, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	deadline, _ := inner.Deadline()
	fm := &FinalMask{dialTCP: func(ctx context.Context, _ net.Destination) (net.Conn, error) {
		if ctx.Value(contextKey{}) != "routing metadata" {
			t.Fatal("lost outer context values")
		}
		if got, ok := ctx.Deadline(); !ok || got.After(deadline) {
			t.Fatal("lost request deadline")
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	if _, err := fm.tcpDialContext(outer)(inner, net.TCPDestination(net.LocalHostIP, 853)); !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("dial was not canceled: %v", err)
	}
}

func TestResolverDialPreservesCallerCancellation(t *testing.T) {
	outer, cancel := context.WithCancel(context.Background())
	cancel()
	fm := &FinalMask{dialTCP: func(ctx context.Context, _ net.Destination) (net.Conn, error) {
		return nil, ctx.Err()
	}}
	if _, err := fm.tcpDialContext(outer)(context.Background(), net.TCPDestination(net.LocalHostIP, 853)); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost outer cancellation: %v", err)
	}
}
