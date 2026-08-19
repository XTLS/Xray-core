package conf_test

import (
	"encoding/json"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
)

func TestValidateOutboundTransportSecurity(t *testing.T) {
	mustBuild := func(jsonStr string) error {
		var cfg OutboundDetourConfig
		if err := json.Unmarshal([]byte(jsonStr), &cfg); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		_, err := cfg.Build()
		return err
	}

	tests := []struct {
		name      string
		json      string
		wantErr   bool
		errSubstr string
	}{
		{
			name: "VLESS vnext public none no TLS -> error",
			json: `{
				"protocol": "vless",
				"settings": {"vnext": [{"address": "111.222.213.123","port": 443,"users": [{"id": "27848739-7e62-4138-9fd3-098a63964b6b","encryption": "none"}]}]},
				"streamSettings": {"network": "xhttp"}
			}`,
			wantErr:   true,
			errSubstr: "vless without TLS",
		},
		{
			name: "VLESS new public none no TLS -> error",
			json: `{
				"protocol": "vless",
				"settings": {"address": "8.8.8.8","port": 443,"id": "27848739-7e62-4138-9fd3-098a63964b6b","encryption": "none"},
				"streamSettings": {"network": "xhttp"}
			}`,
			wantErr:   true,
			errSubstr: "vless without TLS",
		},
		{
			name: "VLESS vnext private none no TLS -> pass",
			json: `{
				"protocol": "vless",
				"settings": {"vnext": [{"address": "192.168.1.100","port": 443,"users": [{"id": "27848739-7e62-4138-9fd3-098a63964b6b","encryption": "none"}]}]},
				"streamSettings": {"network": "xhttp"}
			}`,
			wantErr: false,
		},
		{
			name: "VLESS vnext private domain none no TLS -> pass",
			json: `{
				"protocol": "vless",
				"settings": {"vnext": [{"address": "myhost.local","port": 443,"users": [{"id": "27848739-7e62-4138-9fd3-098a63964b6b","encryption": "none"}]}]},
				"streamSettings": {"network": "xhttp"}
			}`,
			wantErr: false,
		},
		{
			name: "VLESS new public non-none encryption no TLS -> pass",
			json: `{
				"protocol": "vless",
				"settings": {"address": "8.8.8.8","port": 443,"id": "27848739-7e62-4138-9fd3-098a63964b6b","encryption": "mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
				"streamSettings": {"network": "xhttp"}
			}`,
			wantErr: false,
		},
		{
			name: "VLESS vnext public non-none encryption no TLS -> pass",
			json: `{
				"protocol": "vless",
				"settings": {"vnext": [{"address": "8.8.8.8","port": 443,"users": [{"id": "27848739-7e62-4138-9fd3-098a63964b6b","encryption": "mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}]},
				"streamSettings": {"network": "xhttp"}
			}`,
			wantErr: false,
		},
		{
			name: "VLESS vnext public none with TLS -> pass",
			json: `{
				"protocol": "vless",
				"settings": {"vnext": [{"address": "111.222.213.123","port": 443,"users": [{"id": "27848739-7e62-4138-9fd3-098a63964b6b","encryption": "none"}]}]},
				"streamSettings": {"network": "xhttp","security": "tls","tlsSettings": {}}
			}`,
			wantErr: false,
		},
		{
			name: "VLESS new public none with reality -> pass",
			json: `{
				"protocol": "vless",
				"settings": {"address": "8.8.8.8","port": 443,"id": "27848739-7e62-4138-9fd3-098a63964b6b","encryption": "none"},
				"streamSettings": {"network": "xhttp","security": "reality","realitySettings": {"publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortId": "0123456789abcdef","serverName": "example.com"}}
			}`,
			wantErr: false,
		},
		{
			name: "Trojan servers public no TLS -> error",
			json: `{
				"protocol": "trojan",
				"settings": {"servers": [{"address": "8.8.8.8","port": 443,"password": "test"}]},
				"streamSettings": {"network": "tcp"}
			}`,
			wantErr:   true,
			errSubstr: "trojan without TLS",
		},
		{
			name: "Trojan servers private no TLS -> pass",
			json: `{
				"protocol": "trojan",
				"settings": {"servers": [{"address": "192.168.1.1","port": 443,"password": "test"}]},
				"streamSettings": {"network": "tcp"}
			}`,
			wantErr: false,
		},
		{
			name: "Trojan new public no TLS -> error",
			json: `{
				"protocol": "trojan",
				"settings": {"address": "8.8.8.8","port": 443,"password": "test"},
				"streamSettings": {"network": "tcp"}
			}`,
			wantErr:   true,
			errSubstr: "trojan without TLS",
		},
		{
			name: "Trojan servers private domain no TLS -> pass",
			json: `{
				"protocol": "trojan",
				"settings": {"servers": [{"address": "myhost.local","port": 443,"password": "test"}]},
				"streamSettings": {"network": "tcp"}
			}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mustBuild(tt.json)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.errSubstr)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected success, got error: %v", err)
			}
			if tt.wantErr && err != nil && tt.errSubstr != "" {
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			}
		})
	}
}
