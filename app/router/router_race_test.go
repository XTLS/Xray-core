package router_test

import (
	"sync"
	"testing"

	. "github.com/xtls/xray-core/app/router"
)

// TestRouterPickRouteReloadNoRace exercises the hot routing path concurrently
// with a runtime rule reload. Before PickRoute snapshotted the rule set under
// the lock, this tripped the race detector (go test -race), because ReloadRules
// reassigns r.rules under the write lock while PickRoute ranged over it with no
// synchronization.
func TestRouterPickRouteReloadNoRace(t *testing.T) {
	r := new(Router)
	cfg := &Config{}
	if err := r.ReloadRules(cfg, false); err != nil {
		t.Fatal(err)
	}
	ctx := withBackground()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 3000; i++ {
			r.PickRoute(ctx)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 3000; i++ {
			_ = r.ReloadRules(cfg, false)
		}
	}()

	wg.Wait()
}
