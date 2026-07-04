package browser_dialer

import (
	"os"
	"testing"

	"github.com/xtls/xray-core/common/platform"
)

func TestReloadEnvSettingsBrowserDialerNoopWhenAddressUnchanged(t *testing.T) {
	t.Cleanup(func() {
		_ = os.Unsetenv(platform.BrowserDialerAddress)
		platform.ReloadEnvSettings()
	})

	t.Setenv(platform.BrowserDialerAddress, "127.0.0.1:0")
	platform.ReloadEnvSettings()
	firstServer := server
	if firstServer == nil {
		t.Fatal("browser dialer server was not started")
	}

	platform.ReloadEnvSettings()
	if server != firstServer {
		t.Fatal("browser dialer server changed when address was unchanged")
	}
}
