package proxyman_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/app/proxyman"
)

func TestTLSSniffingConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config *proxyman.SniffingConfig
		valid  bool
	}{
		{"default", &proxyman.SniffingConfig{}, true},
		{"enabled", &proxyman.SniffingConfig{Enabled: true, DestinationOverride: []string{"tls"}, TlsSniffingTimeout: 3000}, true},
		{"maximum", &proxyman.SniffingConfig{Enabled: true, DestinationOverride: []string{"tls"}, TlsSniffingTimeout: 60000}, true},
		{"too long", &proxyman.SniffingConfig{Enabled: true, DestinationOverride: []string{"tls"}, TlsSniffingTimeout: 60001}, false},
		{"disabled", &proxyman.SniffingConfig{DestinationOverride: []string{"tls"}, TlsSniffingTimeout: 3000}, false},
		{"metadata only", &proxyman.SniffingConfig{Enabled: true, MetadataOnly: true, DestinationOverride: []string{"tls"}, TlsSniffingTimeout: 3000}, false},
		{"no tls", &proxyman.SniffingConfig{Enabled: true, DestinationOverride: []string{"http"}, TlsSniffingTimeout: 3000}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := proto.Marshal(tc.config)
			if err != nil {
				t.Fatal(err)
			}
			var config proxyman.SniffingConfig
			if err := proto.Unmarshal(wire, &config); err != nil {
				t.Fatal(err)
			}
			r, err := proxyman.BuildSniffingRequest(&config)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
			if tc.valid && r.TLSSniffingTimeout != time.Duration(tc.config.TlsSniffingTimeout)*time.Millisecond {
				t.Fatalf("timeout lost: %v", r.TLSSniffingTimeout)
			}
		})
	}
}
