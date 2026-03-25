package proxy_test

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/proxy"
)

func TestUserConnTrackerCancelAll(t *testing.T) {
	tracker := proxy.NewUserConnTracker()

	var cancelCount int32
	makeCancel := func() func() {
		return func() { atomic.AddInt32(&cancelCount, 1) }
	}

	tracker.Register("user@example.com", makeCancel())
	tracker.Register("user@example.com", makeCancel())
	tracker.Register("other@example.com", makeCancel())

	tracker.CancelAll("user@example.com")

	if got := atomic.LoadInt32(&cancelCount); got != 2 {
		t.Errorf("CancelAll: expected 2 cancels called, got %d", got)
	}
}

func TestUserConnTrackerCancelAllDoesNotAffectOtherUsers(t *testing.T) {
	tracker := proxy.NewUserConnTracker()

	var otherCancelled int32
	tracker.Register("other@example.com", func() { atomic.AddInt32(&otherCancelled, 1) })

	tracker.CancelAll("user@example.com")

	if atomic.LoadInt32(&otherCancelled) != 0 {
		t.Error("CancelAll for user@example.com must not cancel other users")
	}
}

func TestUserConnTrackerCancelAllCaseInsensitive(t *testing.T) {
	tracker := proxy.NewUserConnTracker()

	var cancelCount int32
	tracker.Register("user@example.com", func() { atomic.AddInt32(&cancelCount, 1) })

	// CancelAll with different case should still match because callers
	// normalise with strings.ToLower before calling Register/CancelAll.
	tracker.Register("user@example.com", func() { atomic.AddInt32(&cancelCount, 1) })
	tracker.CancelAll("user@example.com")

	if got := atomic.LoadInt32(&cancelCount); got != 2 {
		t.Errorf("expected 2 cancels, got %d", got)
	}
}

func TestUserConnTrackerUnregisterPreventsCancel(t *testing.T) {
	tracker := proxy.NewUserConnTracker()

	var cancelCalled int32
	id := tracker.Register("user@example.com", func() { atomic.AddInt32(&cancelCalled, 1) })

	// Simulate a connection that closed naturally before the user was removed.
	tracker.Unregister("user@example.com", id)

	tracker.CancelAll("user@example.com")

	if atomic.LoadInt32(&cancelCalled) != 0 {
		t.Error("cancel should not be called after Unregister")
	}
}

func TestUserConnTrackerUnregisterCleansEmptyBucket(t *testing.T) {
	tracker := proxy.NewUserConnTracker()

	id := tracker.Register("user@example.com", func() {})
	tracker.Unregister("user@example.com", id)

	// A second CancelAll should be a no-op (no panic, no stale entry).
	tracker.CancelAll("user@example.com")
}

func TestUserConnTrackerMultipleCancelAllNoPanic(t *testing.T) {
	tracker := proxy.NewUserConnTracker()

	tracker.Register("user@example.com", func() {})
	tracker.CancelAll("user@example.com")
	// Second call on an already-cleared email must not panic.
	tracker.CancelAll("user@example.com")
}

func TestUserConnTrackerConcurrentAccess(t *testing.T) {
	tracker := proxy.NewUserConnTracker()

	const goroutines = 50
	const email = "concurrent@example.com"

	var wg sync.WaitGroup
	var totalCancels int32

	// Concurrently register cancels.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tracker.Register(email, func() { atomic.AddInt32(&totalCancels, 1) })
		}()
	}
	wg.Wait()

	tracker.CancelAll(email)

	if got := atomic.LoadInt32(&totalCancels); got != goroutines {
		t.Errorf("concurrent: expected %d cancels, got %d", goroutines, got)
	}
}

func TestUserConnTrackerConcurrentRegisterAndCancel(t *testing.T) {
	tracker := proxy.NewUserConnTracker()

	const email = "race@example.com"
	var wg sync.WaitGroup

	// Hammer Register and CancelAll simultaneously to exercise the mutex.
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			tracker.Register(email, func() {})
		}()
		go func() {
			defer wg.Done()
			tracker.CancelAll(email)
		}()
	}
	wg.Wait()
}
