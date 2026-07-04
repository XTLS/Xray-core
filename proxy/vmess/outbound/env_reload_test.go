package outbound

import (
	"os"
	"testing"

	"github.com/xtls/xray-core/common/platform"
)

func TestReloadEnvSettingsUseVmessPadding(t *testing.T) {
	original, existed := os.LookupEnv(platform.UseVmessPadding)
	_ = os.Unsetenv(platform.UseVmessPadding)
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv(platform.UseVmessPadding, original)
		} else {
			_ = os.Unsetenv(platform.UseVmessPadding)
		}
		platform.ReloadEnvSettings()
	})

	platform.ReloadEnvSettings()
	if enablePadding.Load() {
		t.Fatal("vmess padding should be disabled")
	}

	t.Setenv(platform.UseVmessPadding, "true")
	platform.ReloadEnvSettings()
	if !enablePadding.Load() {
		t.Fatal("vmess padding should be enabled")
	}
}
