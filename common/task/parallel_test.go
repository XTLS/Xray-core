package task_test

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/task"
)

func TestParallelForN_Empty(t *testing.T) {
	called := false
	err := ParallelForN(0, func(i int) error {
		called = true
		return nil
	})
	common.Must(err)
	if called {
		t.Fatal("fn should not be called when n=0")
	}
}

func TestParallelForN_AllIndicesCovered(t *testing.T) {
	const N = 10000
	var seen [N]int32
	err := ParallelForN(N, func(i int) error {
		atomic.AddInt32(&seen[i], 1)
		return nil
	})
	common.Must(err)
	for i := 0; i < N; i++ {
		if seen[i] != 1 {
			t.Fatalf("index %d called %d times, expected 1", i, seen[i])
		}
	}
}

func TestParallelForN_Error(t *testing.T) {
	boom := errors.New("boom")
	err := ParallelForN(1000, func(i int) error {
		if i == 42 {
			return boom
		}
		return nil
	})
	if err != boom {
		t.Fatalf("expected %v, got %v", boom, err)
	}
}
