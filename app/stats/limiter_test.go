package stats_test

import (
	"context"
	"testing"

	. "github.com/xtls/xray-core/app/stats"
	"golang.org/x/time/rate"
)

func TestManager_RateLimiter(t *testing.T) {
	m, err := NewManager(context.Background(), &Config{})
	if err != nil {
		t.Fatal(err)
	}

	name := "test_limiter"
	limit1 := rate.Limit(1000)
	burst1 := 1000

	// 1. Register new limiter
	l1, err := m.GetOrRegisterRateLimiter(name, limit1, burst1)
	if err != nil {
		t.Fatal(err)
	}
	if l1.Limit() != limit1 || l1.Burst() != burst1 {
		t.Errorf("Expected limit %v, burst %d; got %v, %d", limit1, burst1, l1.Limit(), l1.Burst())
	}

	// 2. Get existing limiter
	l2 := m.GetRateLimiter(name)
	if l2 != l1 {
		t.Error("Expected same limiter instance")
	}

	// 3. Update existing limiter via Register (simulating config reload)
	limit2 := rate.Limit(2000)
	burst2 := 2000
	l3, err := m.GetOrRegisterRateLimiter(name, limit2, burst2)
	if err != nil {
		t.Fatal(err)
	}
	if l3 != l1 {
		t.Error("Expected same limiter instance after update")
	}
	if l1.Limit() != limit2 {
		t.Errorf("Expected updated limit %v, got %v", limit2, l1.Limit())
	}
	if l1.Burst() != burst2 {
		t.Errorf("Expected updated burst %d, got %d", burst2, l1.Burst())
	}

	// 4. Unregister
	m.UnregisterRateLimiter(name)
	if m.GetRateLimiter(name) != nil {
		t.Error("Expected limiter to be removed")
	}
}
