package conf_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

func TestMasqueWarpConfig(t *testing.T) {
	creator := func() Buildable {
		return new(MasqueConfig)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	quote := func(s string) string {
		b, _ := json.Marshal(s)
		return string(b)
	}
	server, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&server.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKey}))
	warpInput := func(key string, extra string) string {
		return `{` + extra + `"warp": {"privateKey": ` + quote(key) + `, "publicKey": ` + quote(publicPEM) + `, "address": ["172.16.0.2", "2606:4700:110:8a36::2/128"]}}`
	}
	address := []string{"172.16.0.2/32", "2606:4700:110:8a36::2/128"}

	for _, input := range []string{
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})),
		base64.StdEncoding.EncodeToString(pkcs8),
		base64.StdEncoding.EncodeToString(sec1),
	} {
		runMultiTestCase(t, []TestCase{
			{
				Input:  warpInput(input, ""),
				Parser: loadJSON(creator),
				Output: &masque.Config{
					Host: "cloudflareaccess.com",
					Path: "/",
					Warp: &masque.Warp{PrivateKey: pkcs8, PublicKey: publicKey, Address: address},
				},
			},
		})
	}
	runMultiTestCase(t, []TestCase{
		{
			Input:  warpInput(base64.StdEncoding.EncodeToString(sec1), `"host": "example.com", "path": "/warp", `),
			Parser: loadJSON(creator),
			Output: &masque.Config{
				Host: "example.com",
				Path: "/warp",
				Warp: &masque.Warp{PrivateKey: pkcs8, PublicKey: publicKey, Address: address},
			},
		},
	})

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384DER, err := x509.MarshalPKCS8PrivateKey(p384)
	if err != nil {
		t.Fatal(err)
	}
	ed, err := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	withAddress := func(address string) string {
		return `{"warp": {"privateKey": ` + quote(base64.StdEncoding.EncodeToString(pkcs8)) + `, "publicKey": ` + quote(publicPEM) + `, "address": ` + address + `}}`
	}
	withPublicKey := func(key string) string {
		return `{"warp": {"privateKey": ` + quote(base64.StdEncoding.EncodeToString(pkcs8)) + `, "publicKey": ` + quote(key) + `, "address": ["172.16.0.2"]}}`
	}
	runMultiTestCase(t, []TestCase{
		{
			Input:  withPublicKey(base64.StdEncoding.EncodeToString(publicKey)),
			Parser: loadJSON(creator),
			Output: &masque.Config{
				Host: "cloudflareaccess.com",
				Path: "/",
				Warp: &masque.Warp{PrivateKey: pkcs8, PublicKey: publicKey, Address: []string{"172.16.0.2/32"}},
			},
		},
	})
	for _, input := range []string{
		`{"warp": {}}`,
		withAddress(`[]`),
		withPublicKey(""),
		withPublicKey("not a key"),
		withPublicKey(base64.StdEncoding.EncodeToString([]byte("not a key"))),
		withPublicKey(base64.StdEncoding.EncodeToString(pkcs8)),
		withAddress(`["172.16.0"]`),
		withAddress(`["172.16.0.2", "172.16.0.3"]`),
		withAddress(`["2606:4700::1", "2606:4700::2/128"]`),
		warpInput("not a key", ""),
		warpInput(base64.StdEncoding.EncodeToString([]byte("not a key")), ""),
		warpInput(base64.StdEncoding.EncodeToString(p384DER), ""),
		warpInput(base64.StdEncoding.EncodeToString(ed), ""),
		warpInput(base64.StdEncoding.EncodeToString(pkcs8), `"user": "u", "pass": "p", `),
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
