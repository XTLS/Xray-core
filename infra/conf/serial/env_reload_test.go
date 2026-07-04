package serial

import (
	"testing"

	"github.com/xtls/xray-core/common/platform"
)

func TestReloadEnvSettingsUseStrictJSON(t *testing.T) {
	t.Setenv(platform.UseStrictJSON, "true")
	platform.ReloadEnvSettings()
	if !IsStrictJSONEnabled() {
		t.Fatal("strict JSON env was not applied")
	}

	t.Setenv(platform.UseStrictJSON, "false")
	platform.ReloadEnvSettings()
	if IsStrictJSONEnabled() {
		t.Fatal("strict JSON env was not cleared")
	}
}
