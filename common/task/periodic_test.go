package task_test

import (
	"testing"
	"time"

	"github.com/hosemorinho412/xray-core/common"
	. "github.com/hosemorinho412/xray-core/common/task"
)

func TestPeriodicTaskStop(t *testing.T) {
	value := 0
	task := &Periodic{
		Interval: time.Second * 2,
		Execute: func() error {
			value++
			return nil
		},
	}
	common.Must(task.Start())
	time.Sleep(time.Second * 5)
	common.Must(task.Close())
	if value != 3 {
		t.Fatal("expected 3, but got ", value)
	}
	time.Sleep(time.Second * 4)
	if value != 3 {
		t.Fatal("expected 3, but got ", value)
	}
	common.Must(task.Start())
	time.Sleep(time.Second * 3)
	if value != 5 {
		t.Fatal("Expected 5, but ", value)
	}
	common.Must(task.Close())
}
