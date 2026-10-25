package filesystem_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/platform"
	. "github.com/xtls/xray-core/common/platform/filesystem"
)

func TestResolveAssetRejectsInvalidPath(t *testing.T) {
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
		if _, err := ResolveAsset(file); err == nil {
			t.Fatalf("expected error for %q", file)
		}
	}
}

func TestResolveLuaFile(t *testing.T) {
	t.Chdir(t.TempDir())
	workingDir, err := os.Getwd()
	common.Must(err)
	executable, err := os.Executable()
	common.Must(err)
	file, err := os.CreateTemp(filepath.Dir(executable), "lua-*.lua")
	common.Must(err)
	common.Must(file.Close())
	defer os.Remove(file.Name())

	name := filepath.Base(file.Name())
	paths := []string{
		filepath.Join(t.TempDir(), name),
		filepath.Join(t.TempDir(), name),
		filepath.Join(workingDir, name),
		file.Name(),
	}
	t.Setenv(platform.ConfdirLocation, filepath.Dir(paths[0]))
	t.Setenv(platform.ConfigLocation, filepath.Dir(paths[1]))
	for _, path := range paths[:3] {
		common.Must(os.WriteFile(path, nil, 0o600))
	}
	if got, err := ResolveLuaFile(paths[2]); err != nil || got != paths[2] {
		t.Fatalf("absolute path = %q, %v; want %q", got, err, paths[2])
	}
	for i, want := range paths {
		if i == 2 {
			t.Setenv(platform.ConfdirLocation, "")
			t.Setenv(platform.ConfigLocation, "")
		}
		if got, err := ResolveLuaFile(name); err != nil || got != want {
			t.Fatalf("resolved path = %q, %v; want %q", got, err, want)
		}
		common.Must(os.Remove(want))
	}
	if _, err := ResolveLuaFile(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file error = %v", err)
	}
}
