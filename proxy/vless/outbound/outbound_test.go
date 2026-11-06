package outbound

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/task"
)

func TestReverseNotStartedAfterClose(t *testing.T) {
	var runs atomic.Int32
	r := &Reverse{
		monitorTask: &task.Periodic{
			Interval: time.Hour,
			Execute: func() error {
				runs.Add(1)
				return nil
			},
		},
	}
	r.Close()
	r.Start()
	if n := runs.Load(); n != 0 {
		t.Error("expected the closed reverse not to be started, but its monitor ran", n, "times")
	}
}
