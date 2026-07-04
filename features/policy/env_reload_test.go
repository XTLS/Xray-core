package policy

import (
	"testing"

	"github.com/xtls/xray-core/common/platform"
)

func TestReloadEnvSettingsBufferSize(t *testing.T) {
	t.Setenv(platform.BufferSize, "1")
	platform.ReloadEnvSettings()
	if got := defaultBufferPolicy().PerConnection; got != 1024*1024 {
		t.Fatalf("buffer size = %d, want %d", got, 1024*1024)
	}

	t.Setenv(platform.BufferSize, "0")
	platform.ReloadEnvSettings()
	if got := defaultBufferPolicy().PerConnection; got != -1 {
		t.Fatalf("buffer size = %d, want -1", got)
	}
}
