package extension

import "testing"

func TestObservatoryUpdateDispatcherSubscribeAndUnsubscribe(t *testing.T) {
	var dispatcher ObservatoryUpdateDispatcher
	updates, unsubscribe := dispatcher.SubscribeObservationUpdates()

	dispatcher.NotifyObservationUpdate()
	select {
	case <-updates:
	default:
		t.Fatal("subscriber did not receive an observation update")
	}

	unsubscribe()
	if _, open := <-updates; open {
		t.Fatal("unsubscribed update channel remained open")
	}
	dispatcher.NotifyObservationUpdate()
}

func TestObservatoryUpdateDispatcherCoalescesUnreadUpdates(t *testing.T) {
	var dispatcher ObservatoryUpdateDispatcher
	updates, unsubscribe := dispatcher.SubscribeObservationUpdates()
	defer unsubscribe()

	dispatcher.NotifyObservationUpdate()
	dispatcher.NotifyObservationUpdate()

	select {
	case <-updates:
	default:
		t.Fatal("subscriber did not receive the coalesced update")
	}
	select {
	case <-updates:
		t.Fatal("unread updates were not coalesced")
	default:
	}
}

func TestObservatoryUpdateDispatcherCloseReleasesSubscribers(t *testing.T) {
	var dispatcher ObservatoryUpdateDispatcher
	updates, _ := dispatcher.SubscribeObservationUpdates()

	dispatcher.Close()
	if _, open := <-updates; open {
		t.Fatal("closed dispatcher left its update channel open")
	}

	lateUpdates, _ := dispatcher.SubscribeObservationUpdates()
	if _, open := <-lateUpdates; open {
		t.Fatal("subscription to a closed dispatcher returned an open channel")
	}
}
