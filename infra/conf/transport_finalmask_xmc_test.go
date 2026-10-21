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
		Paddings: []XMCPaddingTurn{
			{Length: "3", Direction: "c2s", Delay: 0},
			{Length: "127-129", Direction: "s2c", Delay: 100},
			{Length: "8388608", Direction: "c2s", Delay: 50},
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
	if config.Paddings[0].Delay != 0 || config.Paddings[1].Delay != 100 || config.Paddings[2].Delay != 50 {
		t.Fatalf("unexpected padding delays: %v, %v, %v", config.Paddings[0].Delay, config.Paddings[1].Delay, config.Paddings[2].Delay)
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
		"negative_delay":       `[{"length": "3", "direction": "c2s", "delay": -1}]`,
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
