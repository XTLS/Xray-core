package conf

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/transport/internet/reality"
)

func TestREALITYClientHelloPolicyBuild(t *testing.T) {
	rawConfig, err := json.Marshal(map[string]any{
		"fingerprint":         "ChRoMe",
		"publicKey":           base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		"clientHelloProfile":  "COMPACT-SINGLE-SEGMENT",
		"clientHelloMaxBytes": 1350,
	})
	if err != nil {
		t.Fatal(err)
	}
	config := new(REALITYConfig)
	if err := json.Unmarshal(rawConfig, config); err != nil {
		t.Fatal(err)
	}

	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	realityConfig := built.(*reality.Config)
	if realityConfig.ClientHelloProfile != reality.ClientHelloProfileCompactSingleSegment {
		t.Fatalf("unexpected clientHelloProfile: %q", realityConfig.ClientHelloProfile)
	}
	if realityConfig.ClientHelloMaxBytes != 1350 {
		t.Fatalf("unexpected clientHelloMaxBytes: %d", realityConfig.ClientHelloMaxBytes)
	}
}

func TestREALITYCompactClientHelloRejectsNonChromeFingerprint(t *testing.T) {
	config := &REALITYConfig{
		Fingerprint:        "firefox",
		PublicKey:          base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		ClientHelloProfile: reality.ClientHelloProfileCompactSingleSegment,
	}

	if _, err := config.Build(); err == nil {
		t.Fatal("expected compact profile with Firefox fingerprint to fail")
	}
}
