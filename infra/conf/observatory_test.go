package conf_test

import (
	"net/http"
	"testing"

	"github.com/xtls/xray-core/app/observatory/burst"
	. "github.com/xtls/xray-core/infra/conf"
)

func TestHealthCheckSettingsBuildResponseValidation(t *testing.T) {
	message, err := (HealthCheckSettings{
		HttpMethod:           http.MethodGet,
		ExpectedStatus:       http.StatusPartialContent,
		MinimumResponseBytes: 32 * 1024,
	}).Build()
	if err != nil {
		t.Fatalf("HealthCheckSettings.Build() returned an error: %v", err)
	}
	config := message.(*burst.HealthPingConfig)
	if config.ExpectedStatus != http.StatusPartialContent {
		t.Fatalf("ExpectedStatus = %d, want %d", config.ExpectedStatus, http.StatusPartialContent)
	}
	if config.MinimumResponseBytes != 32*1024 {
		t.Fatalf("MinimumResponseBytes = %d, want %d", config.MinimumResponseBytes, 32*1024)
	}
}

func TestHealthCheckSettingsRejectsInvalidResponseValidation(t *testing.T) {
	tests := []struct {
		name     string
		settings HealthCheckSettings
	}{
		{
			name:     "invalid status",
			settings: HealthCheckSettings{ExpectedStatus: 99},
		},
		{
			name:     "negative response size",
			settings: HealthCheckSettings{MinimumResponseBytes: -1},
		},
		{
			name:     "response size with HEAD",
			settings: HealthCheckSettings{HttpMethod: http.MethodHead, MinimumResponseBytes: 1},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.settings.Build(); err == nil {
				t.Fatal("HealthCheckSettings.Build() succeeded with invalid response validation")
			}
		})
	}
}
