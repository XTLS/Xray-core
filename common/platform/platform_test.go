package platform_test

import (
	"errors"
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

func TestResolveLuaFile(t *testing.T) {
	workingDir := t.TempDir()
	t.Chdir(workingDir)
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
	t.Setenv(ConfdirLocation, filepath.Dir(paths[0]))
	t.Setenv(ConfigLocation, filepath.Dir(paths[1]))
	for _, path := range paths[:3] {
		common.Must(os.WriteFile(path, nil, 0o600))
	}
	if got, err := ResolveLuaFile(paths[2]); err != nil || got != paths[2] {
		t.Fatalf("absolute path = %q, %v; want %q", got, err, paths[2])
	}
	for i, want := range paths {
		if i == 2 {
			t.Setenv(ConfdirLocation, "")
			t.Setenv(ConfigLocation, "")
		}
		if got, err := ResolveLuaFile(name); err != nil || got != want {
			t.Fatalf("resolved path = %q, %v; want %q", got, err, want)
		}
		common.Must(os.Remove(want))
	}
	if _, err := ResolveLuaFile(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file error = %v", err)
	}

	t.Setenv(ConfdirLocation, filepath.Dir(paths[0]))
	t.Setenv(ConfigLocation, filepath.Dir(paths[1]))
	common.Must(os.Mkdir(paths[0], 0o700))
	common.Must(os.WriteFile(paths[1], nil, 0o600))
	for _, path := range []string{"", name, filepath.Join(t.TempDir(), name)} {
		if _, err := ResolveLuaFile(path); err == nil {
			t.Fatalf("accepted invalid path %q", path)
		}
	}
}
