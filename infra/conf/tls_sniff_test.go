package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
)

func TestTLSSniffingJSON(t *testing.T) {
	for _, tc := range []struct {
		input string
		valid bool
	}{
		{`{"enabled":true,"destOverride":["https"],"tlsSniffingTimeout":3000}`, true},
		{`{"enabled":true,"destOverride":["tls"],"tlsSniffingTimeout":-1}`, false},
		{`{"enabled":true,"destOverride":["tls"],"tlsSniffingTimeout":60001}`, false},
		{`{"enabled":true,"destOverride":["http"],"tlsSniffingTimeout":3000}`, false},
		{`{"enabled":true,"metadataOnly":true,"destOverride":["tls"],"tlsSniffingTimeout":3000}`, false},
	} {
		var config conf.SniffingConfig
		err := json.Unmarshal([]byte(tc.input), &config)
		if err == nil {
			built, buildErr := config.Build()
			err = buildErr
			if err == nil && built.TlsSniffingTimeout != 3000 {
				t.Fatalf("timeout lost: %v", built)
			}
		}
		if (err == nil) != tc.valid {
			t.Fatalf("%s: %v", tc.input, err)
		}
	}
}
