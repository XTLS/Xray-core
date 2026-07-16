package custom

import (
	"sync"
	"testing"
	"time"
)

// TestRegisterOrJoinWaiterFansOutToAllConcurrentCallers reproduces the exact
// scenario that used to orphan a caller forever: many goroutines all call
// WriteTo (via registerOrJoinWaiter) for the same not-yet-established addr
// before the handshake completes. Only the first should be told to send the
// handshake request; all of them must wake up once it completes - the old
// unconditional c.wait[key] = waiter overwrite meant every joiner but the
// last silently replaced (and thus orphaned) whichever waiter was already
// registered, since only the entry actually left in the map ever gets
// woken by tryCompleteHandshake/failWaiters.
func TestRegisterOrJoinWaiterFansOutToAllConcurrentCallers(t *testing.T) {
	c := &udpCustomStandaloneClientConn{
		wait: make(map[string]*udpStandaloneWaiter),
	}
	const n = 32
	const key = "10.0.0.1:1234"

	var wg sync.WaitGroup
	newCount := make(chan bool, n)
	woken := make(chan struct{}, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			waiter, isNew := c.registerOrJoinWaiter(key, nil)
			newCount <- isNew
			select {
			case <-waiter.done:
				woken <- struct{}{}
			case <-time.After(2 * time.Second):
				t.Error("waiter never woke up - orphaned by a concurrent registerOrJoinWaiter overwrite")
			}
		}()
	}

	// Give every goroutine a chance to register/join before completing the
	// handshake, same as the real race window in WriteTo.
	time.Sleep(50 * time.Millisecond)

	c.mu.Lock()
	waiter, ok := c.wait[key]
	c.mu.Unlock()
	if !ok {
		t.Fatal("expected a waiter to be registered")
	}
	close(waiter.done)

	wg.Wait()
	close(newCount)
	close(woken)

	isNewCount := 0
	for v := range newCount {
		if v {
			isNewCount++
		}
	}
	if isNewCount != 1 {
		t.Fatalf("expected exactly 1 caller to be told isNew=true (send the handshake once), got %d", isNewCount)
	}
	wokenCount := 0
	for range woken {
		wokenCount++
	}
	if wokenCount != n {
		t.Fatalf("expected all %d callers to wake up, got %d", n, wokenCount)
	}
}
