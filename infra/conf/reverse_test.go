package conf_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
)

func TestReverseConfig(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"bridges", `{"reverse":{"bridges":[{"tag":"test","domain":"test.example.com"}]}}`},
		{"portals", `{"reverse":{"portals":[{"tag":"test","domain":"test.example.com"}]}}`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var config conf.Config
			if err := json.Unmarshal([]byte(testCase.input), &config); err != nil {
				t.Fatal(err)
			}
			if config.Reverse == nil {
				t.Fatal("legacy reverse input was not recognized")
			}
			_, err := config.Build()
			if err == nil || !strings.Contains(err.Error(), "legacy reverse") || !strings.Contains(err.Error(), "VLESS Reverse Proxy") {
				t.Fatalf("legacy reverse Build() error = %v, want VLESS Reverse migration error", err)
			}
		})
	}
}
