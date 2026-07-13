package conf

import (
	"encoding/json"
	"os"
	"testing"
)

func TestRootEnvAppliesArbitraryValues(t *testing.T) {
	const (
		valueKey = "XRAY_TEST_CONFIG_ENV"
		emptyKey = "XRAY_TEST_CONFIG_EMPTY"
	)
	t.Setenv(valueKey, "before")
	t.Setenv(emptyKey, "before")

	config := new(Config)
	if err := json.Unmarshal([]byte(`{
		"env": {
			"XRAY_TEST_CONFIG_ENV": "configured",
			"XRAY_TEST_CONFIG_EMPTY": ""
		}
	}`), config); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Build(); err != nil {
		t.Fatal(err)
	}

	if got := os.Getenv(valueKey); got != "configured" {
		t.Fatalf("env %q = %q, want %q", valueKey, got, "configured")
	}
	if got := os.Getenv(emptyKey); got != "" {
		t.Fatalf("env %q = %q, want empty", emptyKey, got)
	}
}

func TestEnvConfigOverride(t *testing.T) {
	base := EnvConfig{
		"ONE": "one",
		"TWO": "old",
	}
	override := EnvConfig{
		"TWO":   "new",
		"THREE": "three",
	}
	base.Override(override)

	want := map[string]string{
		"ONE":   "one",
		"TWO":   "new",
		"THREE": "three",
	}
	for key, value := range want {
		if got := base[key]; got != value {
			t.Fatalf("env %q = %q, want %q", key, got, value)
		}
	}
}
