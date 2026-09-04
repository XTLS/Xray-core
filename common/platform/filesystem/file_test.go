package filesystem_test

import (
	"path/filepath"
	"testing"

	. "github.com/xtls/xray-core/common/platform/filesystem"
)

func TestStatAssetRejectsInvalidPath(t *testing.T) {
	for _, file := range []string{
		"",
		".",
		"..",
		"../geoip.dat",
		"nested/..",
		"nested/../geoip.dat",
		"nested//geoip.dat",
		"/geoip.dat",
		"/tmp/geoip.dat",
		`C:\geoip.dat`,
		`C:geoip.dat`,
		`\\server\share\geoip.dat`,
		`nested\geoip.dat`,
		`nested\..\geoip.dat`,
		filepath.Join(t.TempDir(), "geoip.dat"),
	} {
		if _, err := StatAsset(file); err == nil {
			t.Fatalf("expected error for %q", file)
		}
	}
}
