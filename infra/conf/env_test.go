package conf

import (
	"encoding/base64"
	"encoding/json"
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

func envString(value string) *string {
	return &value
}

func allConfigEnvKeys() []string {
	return []string{
		platform.AssetLocation,
		platform.CertLocation,
		platform.UseReadV,
		platform.UseFreedomSplice,
		platform.UseVmessPadding,
		platform.UseCone,
		platform.BufferSize,
		platform.BrowserDialerAddress,
		platform.XUDPLog,
		platform.XUDPBaseKey,
		platform.TunFdKey,
	}
}

func testBaseKey() string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return base64.RawURLEncoding.EncodeToString(key)
}

func TestEnvConfigSettingsIncludesAllConfigKeys(t *testing.T) {
	config := &EnvConfig{
		AssetLocation:    envString("asset"),
		CertLocation:     envString("cert"),
		UseReadV:         envString("enable"),
		UseFreedomSplice: envString("enable"),
		UseVmessPadding:  envString("true"),
		UseCone:          envString("true"),
		BufferSize:       envString("0"),
		BrowserDialer:    envString("127.0.0.1:0"),
		XUDPLog:          envString("true"),
		XUDPBaseKey:      envString(testBaseKey()),
		TunFd:            envString("123"),
	}

	got := map[string]string{}
	for _, setting := range config.Settings() {
		got[setting.Key] = setting.Value
	}

	want := map[string]string{
		platform.AssetLocation:        "asset",
		platform.CertLocation:         "cert",
		platform.UseReadV:             "enable",
		platform.UseFreedomSplice:     "enable",
		platform.UseVmessPadding:      "true",
		platform.UseCone:              "true",
		platform.BufferSize:           "0",
		platform.BrowserDialerAddress: "127.0.0.1:0",
		platform.XUDPLog:              "true",
		platform.XUDPBaseKey:          testBaseKey(),
		platform.TunFdKey:             "123",
	}
	if len(got) != len(want) {
		t.Fatalf("settings count = %d, want %d: %#v", len(got), len(want), got)
	}
	for key, value := range want {
		if got[key] != value {
			t.Fatalf("settings[%q] = %q, want %q", key, got[key], value)
		}
	}
}

func TestRootEnvAppliesAllSupportedKeys(t *testing.T) {
	keys := allConfigEnvKeys()
	restoreEnvKeys(t, keys...)

	want := map[string]string{
		platform.AssetLocation:        "asset",
		platform.CertLocation:         "cert",
		platform.UseReadV:             "enable",
		platform.UseFreedomSplice:     "enable",
		platform.UseVmessPadding:      "true",
		platform.UseCone:              "true",
		platform.BufferSize:           "0",
		platform.BrowserDialerAddress: "127.0.0.1:0",
		platform.XUDPLog:              "true",
		platform.XUDPBaseKey:          testBaseKey(),
		platform.TunFdKey:             "123",
	}

	_, err := (&Config{
		Env: &EnvConfig{
			AssetLocation:    envString(want[platform.AssetLocation]),
			CertLocation:     envString(want[platform.CertLocation]),
			UseReadV:         envString(want[platform.UseReadV]),
			UseFreedomSplice: envString(want[platform.UseFreedomSplice]),
			UseVmessPadding:  envString(want[platform.UseVmessPadding]),
			UseCone:          envString(want[platform.UseCone]),
			BufferSize:       envString(want[platform.BufferSize]),
			BrowserDialer:    envString(want[platform.BrowserDialerAddress]),
			XUDPLog:          envString(want[platform.XUDPLog]),
			XUDPBaseKey:      envString(want[platform.XUDPBaseKey]),
			TunFd:            envString(want[platform.TunFdKey]),
		},
	}).Build()
	if err != nil {
		t.Fatal(err)
	}

	for _, key := range keys {
		if got := os.Getenv(key); got != want[key] {
			t.Fatalf("env %q = %q, want %q", key, got, want[key])
		}
	}
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
		Env: &EnvConfig{
			XUDPLog: envString("true"),
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
	restoreEnvKeys(t, platform.UseStrictJSON, platform.ConfigLocation, platform.ConfdirLocation, platform.XUDPLog, unknownKey)

	var config Config
	err := json.Unmarshal([]byte(`{
		"env": {
			"xray.json.strict": "true",
			"xray.location.config": "/tmp/root-env-config",
			"xray.location.confdir": "/tmp/root-env-confdir",
			"xray.xudp.show": "true",
			"XRAY_TEST_UNKNOWN_ROOT_ENV": "unknown-value"
		}
	}`), &config)
	if err != nil {
		t.Fatal(err)
	}

	_, err = config.Build()
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
		Env: &EnvConfig{
			AssetLocation: envString("first-asset"),
			XUDPLog:       envString("false"),
		},
	}
	config.Override(&Config{
		Env: &EnvConfig{
			XUDPLog: envString("true"),
		},
	}, "tail.json")

	if got := *config.Env.AssetLocation; got != "first-asset" {
		t.Fatalf("asset env = %q", got)
	}
	if got := *config.Env.XUDPLog; got != "true" {
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
		Env: &EnvConfig{
			XUDPLog: envString(""),
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
		Env: &EnvConfig{
			XUDPBaseKey: envString("invalid"),
		},
	}).Build()
	if err == nil {
		t.Fatal("Build() error = nil, want invalid xudp basekey error")
	}
	if !strings.Contains(err.Error(), platform.XUDPBaseKey) {
		t.Fatalf("Build() error = %v, want %s", err, platform.XUDPBaseKey)
	}
}
