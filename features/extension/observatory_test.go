package extension

import "testing"

func TestObservatoryUpdateDispatcherSubscribeAndUnsubscribe(t *testing.T) {
	var dispatcher ObservatoryUpdateDispatcher
	updates := 0
	unsubscribe := dispatcher.SubscribeObservationUpdates(func() { updates++ })

	dispatcher.NotifyObservationUpdate()
	unsubscribe()
	dispatcher.NotifyObservationUpdate()

	if updates != 1 {
		t.Fatalf("updates = %d, want 1", updates)
	}
}
