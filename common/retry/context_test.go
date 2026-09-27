package retry_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/retry"
)

func TestContextCancelsBackoffWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	done := make(chan error, 1)
	calls := 0
	go func() {
		done <- retry.ExponentialBackoffContext(ctx, 5, 60000).On(func() error {
			calls++
			if calls == 2 {
				close(entered)
			}
			return errors.New("failed")
		})
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not cancel")
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}
