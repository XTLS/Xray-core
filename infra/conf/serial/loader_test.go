package serial_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf/serial"
)

func TestDecodeJSONConfig_RejectsUnknownFields(t *testing.T) {
	unknownField := `{
		"outbound": [{
			"protocol": "freedom"
		}]
	}`
	reader := bytes.NewReader([]byte(unknownField))
	_, err := serial.DecodeJSONConfig(reader)
	if err == nil {
		t.Fatal("expected error for unknown field 'outbound', got nil")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected error about unknown field, got: %v", err)
	}
}

func TestDecodeJSONConfig_AllowsUnknownWhenPermissive(t *testing.T) {
	t.Setenv("XRAY_JSON_STRICT", "false")
	unknownField := `{
		"outbound": [{
			"protocol": "freedom"
		}]
	}`
	reader := bytes.NewReader([]byte(unknownField))
	_, err := serial.DecodeJSONConfig(reader)
	if err != nil {
		t.Fatalf("expected no error when XRAY_JSON_STRICT=false, got: %v", err)
	}
}

func TestDecodeJSONConfig_AcceptsValidConfig(t *testing.T) {
	valid := `{
		"log": {
			"loglevel": "info"
		},
		"inbounds": [{
			"port": 1080,
			"listen": "127.0.0.1",
			"protocol": "socks",
			"settings": {
				"auth": "noauth",
				"udp": true
			}
		}]
	}`
	reader := bytes.NewReader([]byte(valid))
	_, err := serial.DecodeJSONConfig(reader)
	if err != nil {
		t.Fatalf("expected no error for valid config, got: %v", err)
	}
}

func TestDecodeTOMLConfig_RejectsUnknownFields(t *testing.T) {
	unknownField := `log_level = "info"
outbound = []`
	reader := bytes.NewReader([]byte(unknownField))
	_, err := serial.DecodeTOMLConfig(reader)
	if err == nil {
		t.Fatal("expected error for unknown field 'outbound' in TOML, got nil")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected error about unknown field, got: %v", err)
	}
}

func TestDecodeYAMLConfig_RejectsUnknownFields(t *testing.T) {
	unknownField := `log:
  loglevel: info
outbound: []`
	reader := bytes.NewReader([]byte(unknownField))
	_, err := serial.DecodeYAMLConfig(reader)
	if err == nil {
		t.Fatal("expected error for unknown field 'outbound' in YAML, got nil")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected error about unknown field, got: %v", err)
	}
}

func TestLoaderError(t *testing.T) {
	testCases := []struct {
		Input  string
		Output string
	}{
		{
			Input: `{
				"log": {
					// abcd
					0,
					"loglevel": "info"
				}
		}`,
			Output: "line 4 char 6",
		},
		{
			Input: `{
				"log": {
					// abcd
					"loglevel": "info",
				}
		}`,
			Output: "line 5 char 5",
		},
		{
			Input: `{
				"inbounds": [{
					"protocol": "test",
					"port": 1
				}]
		}`,
			Output: "parse json config",
		},
		{
			Input: `{
				"inbounds": [{
					"port": 1,
					"listen": 0,
					"protocol": "test"
				}]
		}`,
			Output: "line 1 char 1",
		},
	}
	for _, testCase := range testCases {
		reader := bytes.NewReader([]byte(testCase.Input))
		_, err := serial.LoadJSONConfig(reader)
		errString := err.Error()
		if !strings.Contains(errString, testCase.Output) {
			t.Error("unexpected output from json: ", testCase.Input, ". expected ", testCase.Output, ", but actually ", errString)
		}
	}
}
