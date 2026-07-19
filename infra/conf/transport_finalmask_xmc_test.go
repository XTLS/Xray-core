package conf

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/transport/internet/finalmask/xmc"
)

func TestXMCBuildProfile(t *testing.T) {
	built, err := (&XMC{
		Password: "test-password",
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
}

func TestXMCBuildRequiresProfile(t *testing.T) {
	_, err := (&XMC{Password: "test-password"}).Build()
	if err == nil || !strings.Contains(err.Error(), "profiles are required") {
		t.Fatalf("expected required profiles error, got %v", err)
	}
}
