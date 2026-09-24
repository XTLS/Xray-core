package conf_test

import (
	"encoding/json"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/masque"
)

func TestMasqueConfig(t *testing.T) {
	creator := func() Buildable {
		return new(MasqueConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input:  `{}`,
			Parser: loadJSON(creator),
			Output: &masque.Config{Path: "/.well-known/masque/ip/*/*/"},
		},
		{
			Input: `{
				"host": "example.com:8443",
				"path": "/.well-known/masque/ip/{target}/{ipproto}/",
				"headers": {"Authorization": "Basic dTpw"}
			}`,
			Parser: loadJSON(creator),
			Output: &masque.Config{
				Host:    "example.com:8443",
				Path:    "/.well-known/masque/ip/*/*/",
				Headers: map[string]string{"Authorization": "Basic dTpw"},
			},
		},
		{
			Input:  `{"path": "/masque/ip{?target,ipproto}"}`,
			Parser: loadJSON(creator),
			Output: &masque.Config{Path: "/masque/ip?target=*&ipproto=*"},
		},
	})

	for _, input := range []string{
		`{"path": "/masque/{target}/{ipproto}/{dns}"}`,
		`{"path": "masque"}`,
		`{"host": "example.com/path"}`,
		`{"headers": {"host": "example.com"}}`,
		`{"headers": {"Capsule-Protocol": "?0"}}`,
		`{"headers": {"X Token": "a"}}`,
		`{"headers": {"X-Token": "a\r\nb"}}`,
	} {
		if _, err := loadJSON(creator)(input); err == nil {
			t.Errorf("expected an error for %s", input)
		}
	}
}

func TestMasqueOutboundConfig(t *testing.T) {
	build := func(s string) error {
		c := new(OutboundDetourConfig)
		if err := json.Unmarshal([]byte(s), c); err != nil {
			return err
		}
		_, err := c.Build()
		return err
	}

	if err := build(`{
		"protocol": "masque",
		"settings": {"address": "example.com", "port": 443},
		"streamSettings": {"network": "masque", "security": "tls"},
		"mux": {"enabled": false, "concurrency": -1}
	}`); err != nil {
		t.Error(err)
	}
	for _, input := range []string{
		`{"protocol": "masque", "settings": {"address": "example.com"}, "streamSettings": {"network": "masque", "security": "tls"}}`,
		`{"protocol": "masque", "settings": {"address": "example.com", "port": 443}, "streamSettings": {"network": "masque", "security": "tls"}, "mux": {"enabled": true}}`,
		`{"protocol": "masque", "settings": {"address": "example.com", "port": 443}, "streamSettings": {"network": "masque", "security": "tls"}, "mux": {"enabled": true, "concurrency": -1}}`,
		`{"protocol": "freedom", "streamSettings": {"network": "masque", "security": "tls"}}`,
	} {
		if err := build(input); err == nil {
			t.Errorf("expected an error for %s", input)
		}
	}
}
