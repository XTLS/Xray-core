package conf_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/app/geodata"
	. "github.com/xtls/xray-core/infra/conf"
)

func TestGeodataConfig(t *testing.T) {
	prepareGeodataAssetDir(t)

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
		{
			Input: `{
				"cron": "0 4 * * *",
				"outbound": "proxy",
				"assets": [
					{
						"url": "https://example.com/geoip.dat",
						"file": "geoip.dat",
						"hashUrl": "https://example.com/geoip.dat.sha256sum",
						"hashFile": "geoip.dat.sha256sum",
						"hashType": "sha256"
					}
				]
			}`,
			Parser: loadJSON(creator),
			Output: &geodata.Config{
				Cron:     "0 4 * * *",
				Outbound: "proxy",
				Assets: []*geodata.Asset{
					{
						Url:      "https://example.com/geoip.dat",
						File:     "geoip.dat",
						HashUrl:  "https://example.com/geoip.dat.sha256sum",
						HashFile: "geoip.dat.sha256sum",
						HashType: "sha256",
					},
				},
			},
		},
	})
}

func TestGeodataAssetConfig(t *testing.T) {
	prepareGeodataAssetDir(t)

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

func TestGeodataAssetConfigWithHash(t *testing.T) {
	prepareGeodataAssetDir(t)

	asset, err := (&GeodataAssetConfig{
		URL:      "https://example.com/geoip.dat",
		File:     "geoip.dat",
		HashURL:  "https://example.com/geoip.dat.sha256sum",
		HashFile: "geoip.dat.sha256sum",
		HashType: "sha-512/256",
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if asset.HashType != "sha512/256" {
		t.Fatalf("unexpected hash type: %s", asset.HashType)
	}
}

func TestGeodataAssetConfigWithDefaultHashType(t *testing.T) {
	prepareGeodataAssetDir(t)

	asset, err := (&GeodataAssetConfig{
		URL:      "https://example.com/geoip.dat",
		File:     "geoip.dat",
		HashURL:  "https://example.com/geoip.dat.sha256sum",
		HashFile: "geoip.dat.sha256sum",
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if asset.HashType != geodata.DefaultHashType {
		t.Fatalf("unexpected hash type: %s", asset.HashType)
	}
}

func TestGeodataAssetConfigWithMissingHashFile(t *testing.T) {
	dir := prepareGeodataAssetDir(t)
	if err := os.Remove(filepath.Join(dir, "geoip.dat.sha256sum")); err != nil {
		t.Fatal(err)
	}

	if _, err := (&GeodataAssetConfig{
		URL:      "https://example.com/geoip.dat",
		File:     "geoip.dat",
		HashURL:  "https://example.com/geoip.dat.sha256sum",
		HashFile: "geoip.dat.sha256sum",
		HashType: "sha256",
	}).Build(); err != nil {
		t.Fatal(err)
	}
}

func TestGeodataAssetConfigInvalidURL(t *testing.T) {
	prepareGeodataAssetDir(t)

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

func TestGeodataAssetConfigInvalidHash(t *testing.T) {
	prepareGeodataAssetDir(t)

	testCases := []GeodataAssetConfig{
		{
			URL:      "https://example.com/geoip.dat",
			File:     "geoip.dat",
			HashURL:  "http://example.com/geoip.dat.sha256sum",
			HashFile: "geoip.dat.sha256sum",
			HashType: "sha256",
		},
		{
			URL:     "https://example.com/geoip.dat",
			File:    "geoip.dat",
			HashURL: "https://example.com/geoip.dat.sha256sum",
		},
		{
			URL:      "https://example.com/geoip.dat",
			File:     "geoip.dat",
			HashFile: "geoip.dat.sha256sum",
		},
		{
			URL:      "https://example.com/geoip.dat",
			File:     "geoip.dat",
			HashType: "sha256",
		},
		{
			URL:      "https://example.com/geoip.dat",
			File:     "geoip.dat",
			HashURL:  "https://example.com/geoip.dat.sha256sum",
			HashFile: "geoip.dat.sha256sum",
			HashType: "sha1",
		},
		{
			URL:      "https://example.com/geoip.dat",
			File:     "geoip.dat",
			HashURL:  "https://example.com/geoip.dat.sha256sum",
			HashFile: "geoip.dat",
			HashType: "sha256",
		},
	}

	for _, testCase := range testCases {
		if _, err := testCase.Build(); err == nil {
			t.Fatalf("expected error for %+v", testCase)
		}
	}
}

func prepareGeodataAssetDir(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	for _, file := range []string{
		"geoip.dat",
		"geosite.dat",
		"geoip.dat.sha256sum",
	} {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(file), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("xray.location.asset", dir)
	return dir
}
