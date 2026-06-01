package observatory

import (
	"context"
	"sync"
	"testing"
)

// TestObserverGetObservationNoRace exercises GetObservation concurrently with
// the prober's status updates. Before GetObservation took the status lock and
// returned a snapshot, this tripped the race detector (go test -race), because
// the prober reassigns the status slice and mutates the status structs in place
// while consumers read them on other goroutines.
func TestObserverGetObservationNoRace(t *testing.T) {
	o := &Observer{}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			o.updateStatusForResult("a", &ProbeResult{Alive: true, Delay: int64(i)})
			o.updateStatusForResult("b", &ProbeResult{Alive: false, LastErrorReason: "x"})
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			report, err := o.GetObservation(context.Background())
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			for _, s := range report.(*ObservationResult).Status {
				_ = s.GetAlive()
				_ = s.GetDelay()
				_ = s.GetOutboundTag()
			}
		}
	}()

	wg.Wait()
}
