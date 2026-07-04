//go:build !wasm && !openbsd
// +build !wasm,!openbsd

package buf

import (
	"testing"

	"github.com/xtls/xray-core/common/platform"
)

func TestReloadEnvSettingsUseReadV(t *testing.T) {
	t.Setenv(platform.UseReadV, "disable")
	platform.ReloadEnvSettings()
	if useReadV() {
		t.Fatal("readv should be disabled")
	}

	t.Setenv(platform.UseReadV, "enable")
	platform.ReloadEnvSettings()
	if !useReadV() {
		t.Fatal("readv should be enabled")
	}
}
