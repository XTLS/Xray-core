package conf

import (
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/transport/internet/finalmask/xmc"
)

func TestXMCBuildProfile(t *testing.T) {
	built, err := (&XMC{
		Password: "test-password",
		Paddings: []XMCPaddingTurn{
			{Length: "3", Direction: "c2s"},
			{Length: "127-129", Direction: "s2c", Delay: "100"},
			{Length: "8388608", Direction: "c2s", Delay: "50-150"},
		},
		Profiles: []XMCProfile{
			{
				Username:          "TestUser",
				UUID:              "00112233-4455-6677-8899-aabbccddeeff",
				TexturesValue:     "textures-value",
				TexturesSignature: "textures-signature",
			},
		},
	}).Build()
	if err != nil {
		t.Fatalf("build XMC config: %v", err)
	}
	config := built.(*xmc.Config)
	if len(config.Profiles) != 1 || len(config.Profiles[0].Uuid) != 16 {
		t.Fatalf("unexpected profiles: %+v", config.Profiles)
	}
	if len(config.Paddings) != 3 || config.Paddings[0].LengthMin != 3 || config.Paddings[0].LengthMax != 3 ||
		config.Paddings[1].LengthMin != 127 || config.Paddings[1].LengthMax != 129 ||
		config.Paddings[2].LengthMin != 8388608 || config.Paddings[2].LengthMax != 8388608 {
		t.Fatalf("unexpected padding: %v", config.Paddings)
	}
	if config.Paddings[0].Direction != 1 || config.Paddings[1].Direction != 2 || config.Paddings[2].Direction != 1 {
		t.Fatalf("unexpected padding directions: %v, %v, %v", config.Paddings[0].Direction, config.Paddings[1].Direction, config.Paddings[2].Direction)
	}
	if config.Paddings[0].DelayMin != 0 || config.Paddings[0].DelayMax != 0 ||
		config.Paddings[1].DelayMin != 100 || config.Paddings[1].DelayMax != 100 ||
		config.Paddings[2].DelayMin != 50 || config.Paddings[2].DelayMax != 150 {
		t.Fatalf("unexpected padding delays: %v, %v, %v", config.Paddings[0].DelayMin, config.Paddings[1].DelayMin, config.Paddings[2].DelayMin)
	}
}

func TestXMCBuildRequiresProfile(t *testing.T) {
	_, err := (&XMC{Password: "test-password"}).Build()
	if err == nil || !strings.Contains(err.Error(), "profiles are required") {
		t.Fatalf("expected required profiles error, got %v", err)
	}
}

func TestXMCBuildRejectsPadding(t *testing.T) {
	for name, padding := range map[string]string{
		"empty_length":         `[{"length": "", "direction": "c2s"}]`,
		"zero_length":          `[{"length": "0", "direction": "c2s"}]`,
		"one_length":           `[{"length": "1", "direction": "c2s"}]`,
		"two_length":           `[{"length": "2", "direction": "c2s"}]`,
		"negative_length":      `[{"length": "-1", "direction": "c2s"}]`,
		"reversed_range":       `[{"length": "64-32", "direction": "c2s"}]`,
		"oversized_length":     `[{"length": "8388609", "direction": "c2s"}]`,
		"huge_length":          `[{"length": "4294967299", "direction": "c2s"}]`,
		"overflow_length":      `[{"length": "9223372036854775808", "direction": "c2s"}]`,
		"invalid_range_format": `[{"length": "1-2-3", "direction": "c2s"}]`,
		"invalid_direction":    `[{"length": "3", "direction": "invalid"}]`,
		"missing_direction":    `[{"length": "3"}]`,
		"numeric_direction":    `[{"length": "3", "direction": "1"}]`,
		"negative_delay":       `[{"length": "3", "direction": "c2s", "delay": "-1"}]`,
		"reversed_delay":       `[{"length": "3", "direction": "c2s", "delay": "10-5"}]`,
		"invalid_delay_format": `[{"length": "3", "direction": "c2s", "delay": "abc"}]`,
		"huge_delay":           `[{"length": "3", "direction": "c2s", "delay": "9223372036854775807"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			var config XMC
			if err := json.Unmarshal([]byte(`{"paddings":`+padding+`}`), &config); err != nil {
				t.Fatal(err)
			}
			config.Password = "test-password"
			config.Profiles = []XMCProfile{{
				Username: "TestUser", UUID: "00112233-4455-6677-8899-aabbccddeeff",
				TexturesValue: "textures-value", TexturesSignature: "textures-signature",
			}}
			if _, err := config.Build(); err == nil {
				t.Fatalf("expected error for padding %s, got success", padding)
			} else {
				t.Logf("correctly rejected: %v", err)
			}
		})
	}
}

func TestXMCBuildRejectsLongPassword(t *testing.T) {
	profile := XMCProfile{
		Username: "TestUser", UUID: "00112233-4455-6677-8899-aabbccddeeff",
		TexturesValue: "textures-value", TexturesSignature: "textures-signature",
	}

	// The verify token and the password share one RSA-1024 PKCS#1 v1.5 block,
	// so the password cannot exceed xmc.MaxLegacyPasswordLength bytes.
	valid := strings.Repeat("p", xmc.MaxLegacyPasswordLength)
	if _, err := (&XMC{Password: valid, Profiles: []XMCProfile{profile}}).Build(); err != nil {
		t.Fatalf("password of %d bytes was rejected: %v", len(valid), err)
	}

	tooLong := valid + "p"
	_, err := (&XMC{Password: tooLong, Profiles: []XMCProfile{profile}}).Build()
	if err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Fatalf("expected a password length error, got %v", err)
	}
}

func TestXMCBuildYggdrasil(t *testing.T) {
	built, err := (&XMC{
		Password: "test-password",
		Yggdrasil: &XMCYggdrasil{
			API:      "https://skin.example.com/api/yggdrasil/",
			Username: "user@example.com",
			Password: "login-password",
			Player:   "TestUser",
		},
	}).Build()
	if err != nil {
		t.Fatalf("build XMC config: %v", err)
	}

	config := built.(*xmc.Config)
	if config.Yggdrasil == nil {
		t.Fatal("yggdrasil config is missing")
	}
	if config.Yggdrasil.Api != "https://skin.example.com/api/yggdrasil" {
		t.Fatalf("yggdrasil api = %q", config.Yggdrasil.Api)
	}
	if config.Yggdrasil.Username != "user@example.com" || config.Yggdrasil.Password != "login-password" || config.Yggdrasil.Player != "TestUser" {
		t.Fatalf("unexpected yggdrasil config: %+v", config.Yggdrasil)
	}
	if config.Password != "" {
		t.Fatalf("password must not be used in yggdrasil mode: %q", config.Password)
	}
	if len(config.RsaPrivateKey) == 0 || len(config.RsaPublicKey) == 0 {
		t.Fatal("yggdrasil mode must build a random rsa key pair")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(config.RsaPrivateKey)
	if err != nil {
		t.Fatalf("parse generated rsa private key: %v", err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal generated rsa public key: %v", err)
	}
	if string(publicKey) != string(config.RsaPublicKey) {
		t.Fatal("generated rsa key pair does not match")
	}
}

func TestXMCBuildYggdrasilServerWithoutCredentials(t *testing.T) {
	built, err := (&XMC{
		Yggdrasil: &XMCYggdrasil{
			API: "https://skin.example.com/api/yggdrasil",
		},
	}).Build()
	if err != nil {
		t.Fatalf("build server-side XMC config: %v", err)
	}
	if built.(*xmc.Config).Yggdrasil == nil {
		t.Fatal("yggdrasil config is missing")
	}
}

func TestXMCBuildRejectsInvalidYggdrasil(t *testing.T) {
	cases := []*XMCYggdrasil{
		{API: ""},
		{API: "ftp://skin.example.com/api/yggdrasil"},
		{API: "https://skin.example.com/api/yggdrasil?foo=bar"},
		{API: "https://skin.example.com/api/yggdrasil", Username: "user@example.com"},
		{API: "https://skin.example.com/api/yggdrasil", Password: "login-password"},
		{API: "https://skin.example.com/api/yggdrasil", Player: "bad name"},
	}
	for i, yggdrasil := range cases {
		_, err := (&XMC{Yggdrasil: yggdrasil}).Build()
		if err == nil {
			t.Fatalf("case %d was accepted: %+v", i, yggdrasil)
		}
	}
}

func TestXMCBuildRequiresPasswordInLegacyMode(t *testing.T) {
	_, err := (&XMC{
		Profiles: []XMCProfile{
			{
				Username:          "TestUser",
				UUID:              "00112233-4455-6677-8899-aabbccddeeff",
				TexturesValue:     "textures-value",
				TexturesSignature: "textures-signature",
			},
		},
	}).Build()
	if err == nil || !strings.Contains(err.Error(), "empty password") {
		t.Fatalf("expected empty password error, got %v", err)
	}
}

func TestXMCBuildDisablesPadding(t *testing.T) {
	profile := XMCProfile{
		Username: "TestUser", UUID: "00112233-4455-6677-8899-aabbccddeeff",
		TexturesValue: "textures-value", TexturesSignature: "textures-signature",
	}

	for name, settings := range map[string]string{
		"explicit_empty_array": `{"paddings": []}`,
		"no_padding_switch":    `{"noPadding": true}`,
	} {
		t.Run(name, func(t *testing.T) {
			var config XMC
			if err := json.Unmarshal([]byte(settings), &config); err != nil {
				t.Fatal(err)
			}
			config.Password = "test-password"
			config.Profiles = []XMCProfile{profile}
			built, err := config.Build()
			if err != nil {
				t.Fatalf("build XMC config: %v", err)
			}
			builtConfig := built.(*xmc.Config)
			if !builtConfig.NoPadding || len(builtConfig.Paddings) != 0 {
				t.Fatalf("padding was not disabled: %+v", builtConfig)
			}
		})
	}

	var config XMC
	if err := json.Unmarshal([]byte(`{"noPadding": true, "paddings": [{"length": "3", "direction": "c2s"}]}`), &config); err != nil {
		t.Fatal(err)
	}
	config.Password = "test-password"
	config.Profiles = []XMCProfile{profile}
	if _, err := config.Build(); err == nil || !strings.Contains(err.Error(), "exclusive") {
		t.Fatalf("expected an exclusive padding error, got %v", err)
	}
}
