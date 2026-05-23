package filesystem_test

import (
	"os"
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

func TestResolveAssetPathAllowsMissingFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("xray.location.asset", dir)

	path, err := ResolveAssetPath("missing.dat")
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, "missing.dat") {
		t.Fatalf("unexpected path: %s", path)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("expected file to stay missing")
	}
}

func TestResolveAssetPathRejectsInvalidPath(t *testing.T) {
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
		if _, err := ResolveAssetPath(file); err == nil {
			t.Fatalf("expected error for %q", file)
		}
	}
}
