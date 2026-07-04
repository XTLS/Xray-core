package freedom

import (
	"testing"

	"github.com/xtls/xray-core/common/platform"
)

func TestReloadEnvSettingsUseSplice(t *testing.T) {
	t.Setenv(platform.UseFreedomSplice, "disable")
	platform.ReloadEnvSettings()
	if useSplice.Load() {
		t.Fatal("splice should be disabled")
	}

	t.Setenv(platform.UseFreedomSplice, "enable")
	platform.ReloadEnvSettings()
	if !useSplice.Load() {
		t.Fatal("splice should be enabled")
	}
}
