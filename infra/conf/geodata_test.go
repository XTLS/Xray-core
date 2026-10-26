package conf_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/geodata"
	. "github.com/xtls/xray-core/infra/conf"
)

func TestGeodataConfig(t *testing.T) {
	t.Setenv("xray.location.asset", filepath.Join("..", "..", "resources"))

	creator := func() Buildable {
		return new(GeodataConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"cron": "0 4 * * *",
				"outbound": "proxy",
				"assets": [
					{"url": "https://example.com/geoip.dat", "file": "geoip.dat"},
					{"url": "https://example.com/geosite.dat", "file": "geosite.dat"}
				]
			}`,
			Parser: loadJSON(creator),
			Output: &geodata.Config{
				Cron:     "0 4 * * *",
				Outbound: "proxy",
				Assets: []*geodata.Asset{
					{Url: "https://example.com/geoip.dat", File: "geoip.dat"},
					{Url: "https://example.com/geosite.dat", File: "geosite.dat"},
				},
			},
		},
	})
}

func TestGeodataAssetConfig(t *testing.T) {
	t.Setenv("xray.location.asset", filepath.Join("..", "..", "resources"))

	if _, err := (&GeodataAssetConfig{
		URL:  "https://example.com/geoip.dat",
		File: "geoip.dat",
	}).Build(); err != nil {
		t.Fatal(err)
	}

	if _, err := (&GeodataAssetConfig{
		URL:  "https://example.com/geoip.dat",
		File: "missing.dat",
	}).Build(); err == nil {
		t.Fatal("expected error")
	}
}

func TestGeodataAssetConfigInvalidURL(t *testing.T) {
	t.Setenv("xray.location.asset", filepath.Join("..", "..", "resources"))

	for _, rawURL := range []string{
		"",
		"http://example.com/geoip.dat",
		"ftp://example.com/geoip.dat",
		"https:///geoip.dat",
	} {
		if _, err := (&GeodataAssetConfig{
			URL:  rawURL,
			File: "geoip.dat",
		}).Build(); err == nil {
			t.Fatalf("expected error for %q", rawURL)
		}
	}
}

func TestGeodataAssetConfigFileExtension(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("xray.location.asset", dir)
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{"custom.dat", true},
		{"custom.DAT", true},
		{"launcher.cmd", false},
		{"script.lua", false},
		{"config.json", false},
		{"asset", false},
	} {
		if err := os.WriteFile(filepath.Join(dir, tc.name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := (&GeodataAssetConfig{
			URL:  "https://example.com/download",
			File: tc.name,
		}).Build()
		if tc.valid {
			if err != nil {
				t.Fatalf("Build(%q): %v", tc.name, err)
			}
		} else if err == nil || !strings.Contains(err.Error(), "extension must be .dat") {
			t.Fatalf("Build(%q) = %v; want .dat extension error", tc.name, err)
		}
	}
}
