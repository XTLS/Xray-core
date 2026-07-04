package platform_test

import (
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/platform"
)

func TestEnvReloadRegistry(t *testing.T) {
	var calls atomic.Int32

	platform.RegisterEnvReload(func() error {
		calls.Add(1)
		return nil
	})
	if got := calls.Load(); got != 1 {
		t.Fatalf("calls after register = %d, want 1", got)
	}

	if err := platform.ReloadEnvSettings(); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("calls after reload = %d, want 2", got)
	}
}
