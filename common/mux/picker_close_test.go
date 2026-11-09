package mux

import (
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common/signal/done"
)

type pickerCloseFactory struct {
	created int
}

func (f *pickerCloseFactory) Create() (*ClientWorker, error) {
	f.created++
	return &ClientWorker{
		sessionManager: NewSessionManager(),
		done:           done.New(),
		strategy:       ClientStrategy{MaxConnection: 1},
	}, nil
}

func TestIncrementalWorkerPickerClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		factory := new(pickerCloseFactory)
		picker := &IncrementalWorkerPicker{Factory: factory}
		manager := &ClientManager{Picker: picker}
		defer manager.Close()

		first, err := picker.PickAvailable()
		if err != nil {
			t.Fatal(err)
		}
		first.sessionManager.Allocate(&first.strategy, nil, nil)
		second, err := picker.PickAvailable()
		if err != nil || first == second {
			t.Fatalf("expected a second worker, got %p with error %v", second, err)
		}

		for range 2 {
			if err := manager.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if !first.Closed() || !second.Closed() {
			t.Fatal("manager did not close both workers")
		}
		if worker, err := picker.PickAvailable(); worker != nil || !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("closed picker returned %p, %v", worker, err)
		}
		if factory.created != 2 {
			t.Fatalf("created %d workers, want 2", factory.created)
		}

		time.Sleep(31 * time.Second)
		synctest.Wait()
		if picker.cleanupTimer != nil || len(picker.workers) != 0 {
			t.Fatal("picker retained cleanup state after close")
		}
	})
}
