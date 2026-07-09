package platform_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/platform"
)

func TestNormalizeEnvName(t *testing.T) {
	cases := []struct {
		input  string
		output string
	}{
		{
			input:  "a",
			output: "A",
		},
		{
			input:  "a.a",
			output: "A_A",
		},
		{
			input:  "A.A.B",
			output: "A_A_B",
		},
	}
	for _, test := range cases {
		if v := NormalizeEnvName(test.input); v != test.output {
			t.Error("unexpected output: ", v, " want ", test.output)
		}
	}
}

func TestCanonicalConfigEnvKey(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		output    string
		supported bool
	}{
		{
			name:      "dotted key",
			input:     "xray.location.asset",
			output:    AssetLocation,
			supported: true,
		},
		{
			name:      "normalized key",
			input:     "XRAY_LOCATION_ASSET",
			output:    AssetLocation,
			supported: true,
		},
		{
			name:      "pre-load key",
			input:     "xray.json.strict",
			supported: false,
		},
		{
			name:      "unknown key",
			input:     "XRAY_UNKNOWN",
			supported: false,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			output, supported := CanonicalConfigEnvKey(test.input)
			if supported != test.supported {
				t.Fatal("supported: ", supported, " want ", test.supported)
			}
			if output != test.output {
				t.Fatal("output: ", output, " want ", test.output)
			}
		})
	}
}

func TestEnvFlag(t *testing.T) {
	v := EnvFlag{
		Name: "xxxxx.y",
	}.GetValueAsInt(10)
	if v != 10 {
		t.Error("env value: ", v)
	}
}

func TestGetAssetLocation(t *testing.T) {
	exec, err := os.Executable()
	common.Must(err)

	loc := GetAssetLocation("t")
	if filepath.Dir(loc) != filepath.Dir(exec) {
		t.Error("asset dir: ", loc, " not in ", exec)
	}

	os.Setenv("xray.location.asset", "/xray")
	if runtime.GOOS == "windows" {
		if v := GetAssetLocation("t"); v != "\\xray\\t" {
			t.Error("asset loc: ", v)
		}
	} else {
		if v := GetAssetLocation("t"); v != "/xray/t" {
			t.Error("asset loc: ", v)
		}
	}
}
