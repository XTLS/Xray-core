package xudp

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/xtls/xray-core/common/platform"
)

func TestReloadEnvSettingsXUDP(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	t.Setenv(platform.XUDPLog, "true")
	t.Setenv(platform.XUDPBaseKey, base64.RawURLEncoding.EncodeToString(key))
	platform.ReloadEnvSettings()

	if !Show.Load() {
		t.Fatal("xudp show should be enabled")
	}
	if got := ensureBaseKey(); !bytes.Equal(got, key) {
		t.Fatalf("base key = %v, want %v", got, key)
	}

	t.Setenv(platform.XUDPLog, "false")
	platform.ReloadEnvSettings()
	if Show.Load() {
		t.Fatal("xudp show should be disabled")
	}
	if got := ensureBaseKey(); !bytes.Equal(got, key) {
		t.Fatal("base key should be retained when env is unchanged")
	}
}

func TestReloadEnvSettingsXUDPInvalidBaseKey(t *testing.T) {
	t.Setenv(platform.XUDPBaseKey, "invalid")
	if err := platform.ReloadEnvSettings(); err == nil {
		t.Fatal("ReloadEnvSettings() error = nil, want invalid base key error")
	}
}
