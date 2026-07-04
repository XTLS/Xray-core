package conf

import (
	"os"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/xudp"
)

func restoreEnvKeys(t *testing.T, keys ...string) {
	t.Helper()
	type value struct {
		text   string
		exists bool
	}
	originals := map[string]value{}
	for _, key := range keys {
		text, exists := os.LookupEnv(key)
		originals[key] = value{text: text, exists: exists}
	}
	t.Cleanup(func() {
		for _, key := range keys {
			original := originals[key]
			if original.exists {
				_ = os.Setenv(key, original.text)
			} else {
				_ = os.Unsetenv(key)
			}
		}
		_ = platform.ReloadEnvSettings()
	})
}

func TestRootEnvOverridesExternalReloadableEnv(t *testing.T) {
	restoreEnvKeys(t, platform.XUDPLog)
	_ = os.Setenv(platform.XUDPLog, "false")
	if err := platform.ReloadEnvSettings(); err != nil {
		t.Fatal(err)
	}
	if xudp.Show.Load() {
		t.Fatal("xudp log should start disabled")
	}

	_, err := (&Config{
		Env: map[string]string{
			platform.XUDPLog: "true",
		},
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if !xudp.Show.Load() {
		t.Fatal("root env did not override external xudp log env")
	}
}

func TestRootEnvIgnoresPreloadAndUnknownKeys(t *testing.T) {
	const unknownKey = "XRAY_TEST_UNKNOWN_ROOT_ENV"
	restoreEnvKeys(t, platform.UseStrictJSON, platform.ConfigLocation, platform.ConfdirLocation, unknownKey)

	_, err := (&Config{
		Env: map[string]string{
			platform.UseStrictJSON:   "true",
			platform.ConfigLocation:  "/tmp/root-env-config",
			platform.ConfdirLocation: "/tmp/root-env-confdir",
			unknownKey:               "unknown-value",
		},
	}).Build()
	if err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{platform.UseStrictJSON, platform.ConfigLocation, platform.ConfdirLocation, unknownKey} {
		if _, found := os.LookupEnv(key); found {
			t.Fatalf("root env should not set unsupported key %q", key)
		}
	}
}

func TestRootEnvMergeOverride(t *testing.T) {
	config := &Config{
		Env: map[string]string{
			platform.AssetLocation: "first-asset",
			platform.XUDPLog:       "false",
		},
	}
	config.Override(&Config{
		Env: map[string]string{
			platform.XUDPLog: "true",
		},
	}, "tail.json")

	if got := config.Env[platform.AssetLocation]; got != "first-asset" {
		t.Fatalf("asset env = %q", got)
	}
	if got := config.Env[platform.XUDPLog]; got != "true" {
		t.Fatalf("xudp log env = %q", got)
	}
}

func TestRootEnvEmptyValueDoesNotUnset(t *testing.T) {
	restoreEnvKeys(t, platform.XUDPLog)
	_ = os.Setenv(platform.XUDPLog, "true")
	if err := platform.ReloadEnvSettings(); err != nil {
		t.Fatal(err)
	}
	if !xudp.Show.Load() {
		t.Fatal("xudp log should start enabled")
	}

	_, err := (&Config{
		Env: map[string]string{
			platform.XUDPLog: "",
		},
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if !xudp.Show.Load() {
		t.Fatal("empty root env value should not unset existing env")
	}
}

func TestRootEnvInvalidXUDPBaseKeyReturnsConfigError(t *testing.T) {
	restoreEnvKeys(t, platform.XUDPBaseKey)

	_, err := (&Config{
		Env: map[string]string{
			platform.XUDPBaseKey: "invalid",
		},
	}).Build()
	if err == nil {
		t.Fatal("Build() error = nil, want invalid xudp basekey error")
	}
	if !strings.Contains(err.Error(), platform.XUDPBaseKey) {
		t.Fatalf("Build() error = %v, want %s", err, platform.XUDPBaseKey)
	}
}
