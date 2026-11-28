package retry_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	. "github.com/xtls/xray-core/common/retry"
)

var errorTestOnly = errors.New("this is a fake error")

func TestNoRetry(t *testing.T) {
	startTime := time.Now().Unix()
	err := Timed(10, 100000).On(func() error {
		return nil
	})
	endTime := time.Now().Unix()

	common.Must(err)
	if endTime < startTime {
		t.Error("endTime < startTime: ", startTime, " -> ", endTime)
	}
}

func TestRetryOnce(t *testing.T) {
	startTime := time.Now()
	called := 0
	err := Timed(10, 1000).On(func() error {
		if called == 0 {
			called++
			return errorTestOnly
		}
		return nil
	})
	duration := time.Since(startTime)

	common.Must(err)
	if v := int64(duration / time.Millisecond); v < 900 {
		t.Error("duration: ", v)
	}
}

func TestRetryMultiple(t *testing.T) {
	startTime := time.Now()
	called := 0
	err := Timed(10, 1000).On(func() error {
		if called < 5 {
			called++
			return errorTestOnly
		}
		return nil
	})
	duration := time.Since(startTime)

	common.Must(err)
	if v := int64(duration / time.Millisecond); v < 4900 {
		t.Error("duration: ", v)
	}
}

func TestRetryExhausted(t *testing.T) {
	startTime := time.Now()
	called := 0
	err := Timed(2, 1000).On(func() error {
		called++
		return errorTestOnly
	})
	duration := time.Since(startTime)

	if errors.Cause(err) != ErrRetryFailed {
		t.Error("cause: ", err)
	}

	if v := int64(duration / time.Millisecond); v < 1900 {
		t.Error("duration: ", v)
	}
}

func TestExponentialBackoff(t *testing.T) {
	startTime := time.Now()
	called := 0
	err := ExponentialBackoff(10, 100).On(func() error {
		called++
		return errorTestOnly
	})
	duration := time.Since(startTime)

	if errors.Cause(err) != ErrRetryFailed {
		t.Error("cause: ", err)
	}
	if v := int64(duration / time.Millisecond); v < 4000 {
		t.Error("duration: ", v)
	}
}

type backoffWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *backoffWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestExponentialBackoffContextStopsDuringWait(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	waiter := &backoffWaitContext{Context: ctx, waiting: make(chan struct{})}
	done := make(chan error, 1)
	attempts := 0
	go func() {
		done <- ExponentialBackoffContext(waiter, 5, 10000).On(func() error {
			attempts++
			return errorTestOnly
		})
	}()

	select {
	case <-waiter.waiting:
	case <-time.After(time.Second):
		t.Fatal("retry did not enter the backoff wait")
	}
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled || attempts != 2 {
			t.Fatalf("retry returned %v after %d attempts", err, attempts)
		}
	case <-time.After(time.Second):
		t.Fatal("retry remained in backoff after cancellation")
	}
}

func TestExponentialBackoffContextKeepsAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	attempts := 0
	err := ExponentialBackoffContext(ctx, 3, 1).On(func() error {
		attempts++
		return errorTestOnly
	})
	if errors.Cause(err) != ErrRetryFailed || attempts != 3 {
		t.Fatalf("retry returned %v after %d attempts", err, attempts)
	}

	cancel()
	err = ExponentialBackoffContext(ctx, 3, 1).On(func() error {
		t.Fatal("retry admitted an attempt for a canceled context")
		return nil
	})
	if err != context.Canceled {
		t.Fatalf("retry with canceled context returned %v", err)
	}
}
