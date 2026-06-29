package main

import (
	"os"
	"testing"

	"github.com/xtls/xray-core/common/cmdarg"
)

func TestApplyRunEnvVars(t *testing.T) {
	tests := []struct {
		name  string
		args  cmdarg.Arg
		key   string
		value string
	}{
		{
			name:  "sets value",
			args:  cmdarg.Arg{"XRAY_TEST_ENV_VALUE=enabled"},
			key:   "XRAY_TEST_ENV_VALUE",
			value: "enabled",
		},
		{
			name:  "last value wins",
			args:  cmdarg.Arg{"XRAY_TEST_ENV_DUP=first", "XRAY_TEST_ENV_DUP=second"},
			key:   "XRAY_TEST_ENV_DUP",
			value: "second",
		},
		{
			name:  "allows empty value",
			args:  cmdarg.Arg{"XRAY_TEST_ENV_EMPTY="},
			key:   "XRAY_TEST_ENV_EMPTY",
			value: "",
		},
		{
			name:  "preserves equals in value",
			args:  cmdarg.Arg{"XRAY_TEST_ENV_EQUALS=a=b"},
			key:   "XRAY_TEST_ENV_EQUALS",
			value: "a=b",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Cleanup(func() {
				os.Unsetenv(test.key)
			})

			if err := applyRunEnvVars(test.args); err != nil {
				t.Fatalf("applyRunEnvVars() error = %v", err)
			}
			got, ok := os.LookupEnv(test.key)
			if !ok {
				t.Fatalf("environment variable %q was not set", test.key)
			}
			if got != test.value {
				t.Fatalf("environment variable %q = %q, want %q", test.key, got, test.value)
			}
		})
	}
}

func TestApplyRunEnvVarsRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name string
		args cmdarg.Arg
	}{
		{
			name: "missing equals",
			args: cmdarg.Arg{"XRAY_TEST_ENV_INVALID"},
		},
		{
			name: "empty key",
			args: cmdarg.Arg{"=value"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := applyRunEnvVars(test.args); err == nil {
				t.Fatal("applyRunEnvVars() error = nil, want non-nil")
			}
		})
	}
}
