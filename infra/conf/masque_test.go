package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	. "github.com/xtls/xray-core/infra/conf"
	masqueproxy "github.com/xtls/xray-core/proxy/masque"
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
		{
			Input:  `{"user": "u", "pass": "p:q", "headers": {"X-Token": "a"}}`,
			Parser: loadJSON(creator),
			Output: &masque.Config{
				Path:    "/.well-known/masque/ip/*/*/",
				Headers: map[string]string{"Authorization": "Basic dTpwOnE=", "X-Token": "a"},
			},
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
		`{"user": "u:v", "pass": "p"}`,
		`{"user": "u", "pass": "p", "headers": {"authorization": "Basic dTpw"}}`,
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

func TestMasqueServerConfig(t *testing.T) {
	creator := func() Buildable {
		return new(MasqueServerConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"users": [{"email": "u@example.com", "pass": "p", "level": 1}],
				"address": ["10.13.0.1/24", "fd13::1/64"],
				"mtu": 1400
			}`,
			Parser: loadJSON(creator),
			Output: &masqueproxy.ServerConfig{
				Users: []*protocol.User{{
					Email:   "u@example.com",
					Level:   1,
					Account: serial.ToTypedMessage(&masqueproxy.Account{Password: "p"}),
				}},
				Address: []string{"10.13.0.1/24", "fd13::1/64"},
				Mtu:     1400,
			},
		},
		{
			Input:  `{"clients": [{"email": "u", "pass": "p:q"}], "address": ["10.13.0.1/24"]}`,
			Parser: loadJSON(creator),
			Output: &masqueproxy.ServerConfig{
				Users: []*protocol.User{{
					Email:   "u",
					Account: serial.ToTypedMessage(&masqueproxy.Account{Password: "p:q"}),
				}},
				Address: []string{"10.13.0.1/24"},
			},
		},
		{
			Input:  `{"address": ["10.13.0.1/24"]}`,
			Parser: loadJSON(creator),
			Output: &masqueproxy.ServerConfig{
				Address: []string{"10.13.0.1/24"},
			},
		},
	})

	for _, input := range []string{
		`{"users": [{"email": "u:v", "pass": "p"}], "address": ["10.13.0.1/24"]}`,
		`{"users": [{"email": "", "pass": "p"}], "address": ["10.13.0.1/24"]}`,
		`{"users": [{"pass": "p"}], "address": ["10.13.0.1/24"]}`,
		`{"users": [{"email": "u", "pass": ""}], "address": ["10.13.0.1/24"]}`,
		`{"users": [{"email": "u", "pass": "p"}, {"email": "U", "pass": "q"}], "address": ["10.13.0.1/24"]}`,
		`{"users": [{"email": "u", "pass": "p"}]}`,
		`{"users": [{"email": "u", "pass": "p"}], "address": ["10.13.0.1"]}`,
		`{"users": [{"email": "u", "pass": "p"}], "address": ["10.13.0.1/24", "10.14.0.1/24"]}`,
		`{"users": [{"email": "u", "pass": "p"}], "address": ["fd13::1/64", "fd14::1/64"]}`,
		`{"users": [{"email": "u", "pass": "p"}], "address": ["10.13.0.1/24"], "mtu": 1000}`,
		`{"users": [{"email": "u", "pass": "p"}], "address": ["10.13.0.1/24"], "mtu": 70000}`,
	} {
		if _, err := loadJSON(creator)(input); err == nil {
			t.Errorf("expected an error for %s", input)
		}
	}
}

func TestMasqueInboundConfig(t *testing.T) {
	build := func(s string) error {
		c := new(InboundDetourConfig)
		if err := json.Unmarshal([]byte(s), c); err != nil {
			return err
		}
		_, err := c.Build()
		return err
	}

	if err := build(`{
		"protocol": "masque",
		"port": 443,
		"settings": {"users": [{"email": "u@example.com", "pass": "p"}], "address": ["10.13.0.1/24"]},
		"streamSettings": {"network": "masque", "security": "tls"}
	}`); err != nil {
		t.Error(err)
	}
	if err := build(`{
		"protocol": "vless",
		"port": 443,
		"settings": {"users": [{"id": "27848739-7e62-4138-9fd3-098a63964b6b"}], "decryption": "none"},
		"streamSettings": {"network": "masque", "security": "tls"}
	}`); err == nil {
		t.Error("expected an error for the masque transport on a vless inbound")
	}
}
