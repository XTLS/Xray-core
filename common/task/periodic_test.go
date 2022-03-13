package task_test

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/task"
)

func TestPeriodicTaskStop(t *testing.T) {
	t.Parallel()

	var period uint64
	task := &Periodic{
		Interval: time.Second * 2,
		Execute: func() error {
			atomic.AddUint64(&period, 1)
			return nil
		},
	}

	var tests = []struct {
		prerun  func()
		postrun func()
		want    uint64
		name    string
	}{
		{
			prerun: func() {
				common.Must(task.Start())
				time.Sleep(time.Second * 5)
				common.Must(task.Close())
			},
			postrun: func() {},
			want:    3,
			name:    "waiting 3 got 3",
		},
		{
			prerun: func() {
				time.Sleep(time.Second * 4)
			},
			postrun: func() {},
			want:    3,
			name:    "waiting 4 got 3",
		},
		{
			prerun: func() {
				common.Must(task.Start())
				time.Sleep(time.Second * 3)
			},
			postrun: func() {
				common.Must(task.Close())
			},
			want: 5,
			name: "waiting 3 got 5",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.prerun()
			got := atomic.LoadUint64(&period)
			if got != test.want {
				t.Fatalf("expected %d, but got %d", test.want, got)
			}
			test.postrun()
		})
	}
}
