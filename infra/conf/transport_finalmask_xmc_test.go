package conf

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/transport/internet/finalmask/xmc"
)

func TestXMCBuildProfile(t *testing.T) {
	built, err := (&XMC{
		Password: "test-password",
		Padding:  []string{"3", "127-129", "8388608"},
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
	if len(config.Padding) != 3 || config.Padding[0].LengthMin != 3 || config.Padding[0].LengthMax != 3 ||
		config.Padding[1].LengthMin != 127 || config.Padding[1].LengthMax != 129 ||
		config.Padding[2].LengthMin != 8388608 || config.Padding[2].LengthMax != 8388608 {
		t.Fatalf("unexpected padding: %v", config.Padding)
	}
}

func TestXMCBuildRequiresProfile(t *testing.T) {
	_, err := (&XMC{Password: "test-password"}).Build()
	if err == nil || !strings.Contains(err.Error(), "profiles are required") {
		t.Fatalf("expected required profiles error, got %v", err)
	}
}

func TestXMCBuildRejectsPadding(t *testing.T) {
	for _, padding := range []string{
		`[""]`, `["0"]`, `["1"]`, `["2"]`, `["-1"]`,
		`["64-32"]`, `["8388609"]`, `["4294967299"]`,
		`["9223372036854775808"]`, `["3", "0"]`, `["3", "1-2-3"]`,
	} {
		t.Run(padding, func(t *testing.T) {
			var config XMC
			if err := json.Unmarshal([]byte(`{"padding":`+padding+`}`), &config); err != nil {
				t.Fatal(err)
			}
			config.Password = "test-password"
			config.Profiles = []XMCProfile{{
				Username: "TestUser", UUID: "00112233-4455-6677-8899-aabbccddeeff",
				TexturesValue: "textures-value", TexturesSignature: "textures-signature",
			}}
			if _, err := config.Build(); err == nil || !strings.Contains(err.Error(), "padding") {
				t.Fatalf("expected padding error, got %v", err)
			}
		})
	}
}
