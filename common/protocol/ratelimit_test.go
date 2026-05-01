package protocol

import "testing"

func TestLimiterRegistrySharesLimiterByEmailAndDirection(t *testing.T) {
	email := "shared-limiter@example.com"

	first := (&MemoryUser{
		Email:            email,
		UplinkSpeedLimit: 1024,
	}).GetUplinkLimiter()
	if first == nil {
		t.Fatal("expected first uplink limiter")
	}
	if got := uint64(first.rate); got != 1024 {
		t.Fatalf("unexpected initial uplink rate: %d", got)
	}

	second := (&MemoryUser{
		Email:            email,
		UplinkSpeedLimit: 4096,
	}).GetUplinkLimiter()
	if second == nil {
		t.Fatal("expected second uplink limiter")
	}
	if first != second {
		t.Fatal("expected limiter to be shared across user refreshes")
	}
	if got := uint64(first.rate); got != 4096 {
		t.Fatalf("expected shared limiter rate to update, got %d", got)
	}
}

func TestLimiterRegistrySeparatesDirections(t *testing.T) {
	email := "directional-limiter@example.com"

	uplink := (&MemoryUser{
		Email:            email,
		UplinkSpeedLimit: 1024,
	}).GetUplinkLimiter()
	downlink := (&MemoryUser{
		Email:              email,
		DownlinkSpeedLimit: 2048,
	}).GetDownlinkLimiter()

	if uplink == nil || downlink == nil {
		t.Fatal("expected both limiters")
	}
	if uplink == downlink {
		t.Fatal("expected uplink and downlink limiters to be separate")
	}
	if got := uint64(uplink.rate); got != 1024 {
		t.Fatalf("unexpected uplink rate: %d", got)
	}
	if got := uint64(downlink.rate); got != 2048 {
		t.Fatalf("unexpected downlink rate: %d", got)
	}
}

func TestRateLimiterSetRateZeroDisablesLimiter(t *testing.T) {
	limiter := NewRateLimiter(1024)
	if limiter == nil {
		t.Fatal("expected limiter")
	}

	limiter.SetRate(0)

	if limiter.rate != 0 {
		t.Fatalf("expected disabled rate, got %f", limiter.rate)
	}
	limiter.Wait(4096)
}
