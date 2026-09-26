package conf_test

import (
	"encoding/base64"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
)

func TestRealityFingerprintRequiresTLS13(t *testing.T) {
	password := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	for _, fingerprint := range []string{
		"360",
		"android",
		"hello360_7_5",
		"hello360_auto",
		"helloandroid_11_okhttp",
		"hellochrome_58",
		"hellochrome_62",
		"hellofirefox_55",
		"hellofirefox_56",
		"helloios_11_1",
		"helloios_12_1",
		"hellorandomized",
		"hellorandomizedalpn",
		"hellorandomizednoalpn",
	} {
		t.Run(fingerprint, func(t *testing.T) {
			_, err := (&REALITYConfig{
				Fingerprint: fingerprint,
				ServerName:  "example.com",
				Password:    password,
			}).Build()
			if err == nil || !strings.Contains(err.Error(), "does not support TLS 1.3") {
				t.Fatalf("expected TLS 1.3 validation error, got %v", err)
			}
		})
	}
}

func TestRealityAcceptsTLS13Fingerprints(t *testing.T) {
	password := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	for _, fingerprint := range []string{
		"chrome",
		"firefox",
		"safari",
		"edge",
		"random",
		"randomized",
		"randomizednoalpn",
	} {
		t.Run(fingerprint, func(t *testing.T) {
			_, err := (&REALITYConfig{
				Fingerprint: fingerprint,
				ServerName:  "example.com",
				Password:    password,
			}).Build()
			if err != nil {
				t.Fatalf("expected a valid REALITY fingerprint, got %v", err)
			}
		})
	}
}
