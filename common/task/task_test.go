package task_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/task"
)

func TestExecuteParallel(t *testing.T) {
	err := RunContext(context.Background(),
		func(context.Context) error {
			time.Sleep(time.Millisecond * 200)
			return errors.New("test")
		}, func(context.Context) error {
			time.Sleep(time.Millisecond * 500)
			return errors.New("test2")
		})

	if r := cmp.Diff(err.Error(), "test"); r != "" {
		t.Error(r)
	}
}

func TestRunContextCancelsSiblings(t *testing.T) {
	secondDone := make(chan struct{})
	err := RunContext(context.Background(),
		func(context.Context) error {
			return errors.New("first failed")
		},
		func(ctx context.Context) error {
			<-ctx.Done()
			close(secondDone)
			return ctx.Err()
		},
	)
	if r := cmp.Diff(err.Error(), "first failed"); r != "" {
		t.Error(r)
	}
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("sibling task was not cancelled")
	}
}

func TestExecuteParallelContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	err := RunContext(ctx, func(context.Context) error {
		time.Sleep(time.Millisecond * 2000)
		return errors.New("test")
	}, func(context.Context) error {
		time.Sleep(time.Millisecond * 5000)
		return errors.New("test2")
	}, func(context.Context) error {
		cancel()
		return nil
	})

	errStr := err.Error()
	if !strings.Contains(errStr, "canceled") {
		t.Error("expected error string to contain 'canceled', but actually not: ", errStr)
	}
}

func BenchmarkExecuteOne(b *testing.B) {
	noop := func() error {
		return nil
	}
	for i := 0; i < b.N; i++ {
		common.Must(Run(context.Background(), noop))
	}
}

func BenchmarkExecuteTwo(b *testing.B) {
	noop := func() error {
		return nil
	}
	for i := 0; i < b.N; i++ {
		common.Must(Run(context.Background(), noop, noop))
	}
}
