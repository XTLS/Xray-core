package serial_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	xlua "github.com/xtls/xray-core/common/lua"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/confloader/external"
	glua "github.com/yuin/gopher-lua"
)

func TestConfigSourceSecurity(t *testing.T) {
	// Keep registered files alive until every file identity check finishes.
	dir := t.TempDir()
	t.Run("polyglots", testConfigLuaPolyglots)
	t.Run("merged", func(t *testing.T) { testMergedConfigCannotRunAsLua(t, dir) })
	t.Run("hardlink", func(t *testing.T) { testConfigHardLinkCannotRunAsLua(t, dir) })
	t.Run("stdin", func(t *testing.T) { testStdinConfigCannotRunAsLua(t, dir) })
}

func testConfigLuaPolyglots(t *testing.T) {
	const luaBody = "polyglotExecuted = true\nfunction HandleRoute() return 'direct' end\n"
	for _, tc := range []struct {
		name   string
		decode func(io.Reader) (*conf.Config, error)
		source string
		script string
	}{
		{"JSON", serial.DecodeJSONConfig, "null = 0\n" + luaBody, ""},
		{"YAML", serial.DecodeYAMLConfig, `--[[: ignored
routing:
  script: payload.lua
--]] --: ignored
_G: assert((function() polyglotExecuted = true; function HandleRoute() return 'direct' end end)())
`, "payload.lua"},
		{"TOML", serial.DecodeTOMLConfig, `routing = { script = "payload.lua" }
-- = """
polyglotExecuted = true
function HandleRoute() return 'direct' end
-- """
`, "payload.lua"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, err := tc.decode(strings.NewReader(tc.source))
			if err != nil {
				t.Fatal(err)
			}
			script := ""
			if config.RouterConfig != nil {
				script = config.RouterConfig.Script
			}
			if script != tc.script {
				t.Fatalf("routing.script = %q, want %q", script, tc.script)
			}
			if built, err := config.Build(); err != nil || built == nil {
				t.Fatalf("config Build failed: %v", err)
			}
			if _, err := serial.DecodeJSONConfigStrict(strings.NewReader(tc.source)); err == nil {
				t.Fatal("strict JSON accepted the polyglot")
			}
			dir := t.TempDir()
			t.Setenv("xray.location.confdir", dir)
			if err := os.WriteFile(filepath.Join(dir, "payload.lua"), []byte(tc.source), 0o600); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(dir, "payload."+strings.ToLower(tc.name))
			if err := os.WriteFile(configPath, []byte(tc.source), 0o600); err != nil {
				t.Fatal(err)
			}
			if program, err := xlua.Compile(configPath); program != nil || err == nil || !strings.Contains(err.Error(), "Lua file extension must be .lua") {
				t.Fatalf("Compile(%q) = %v, %v; want .lua extension rejection", configPath, program, err)
			}
			program, err := xlua.Compile("payload.lua")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			state, err := program.NewState(ctx, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			if state.GetGlobal("polyglotExecuted") != glua.LTrue {
				t.Fatal("Lua top-level code did not execute")
			}
			if err := state.CallByParam(glua.P{Fn: state.GetGlobal("HandleRoute"), NRet: 1, Protect: true}); err != nil {
				t.Fatal(err)
			}
			if got := state.Get(-1); got != glua.LString("direct") {
				t.Fatalf("HandleRoute() = %v, want direct", got)
			}
			t.Logf("config built with routing.script=%q; the same bytes executed as Lua", script)
		})
	}
}

func testMergedConfigCannotRunAsLua(t *testing.T, dir string) {
	t.Setenv("xray.location.confdir", dir)
	base := filepath.Join(dir, "base.lua")
	for format, body := range map[string]string{
		"json": "null = 0\nfunction HandleRoute() return 'direct' end\n",
		"yaml": "_G: assert((function() function HandleRoute() return 'direct' end end)())\n",
		"toml": "-- = \"\"\"\nfunction HandleRoute() return 'direct' end\n-- \"\"\"\n",
	} {
		t.Run(format, func(t *testing.T) {
			path := filepath.Join(dir, format+".lua")
			if err := os.WriteFile(base, []byte(`{"routing":{"script":"`+format+`.lua"}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if program, err := xlua.Compile(path); err != nil || program == nil {
				t.Fatalf("fixture must compile before config loading: %v", err)
			}
			if _, err := serial.BuildConfig([]*core.ConfigSource{
				{Name: base, Format: "json"},
				{Name: path, Format: format},
			}); err != nil {
				t.Fatal(err)
			}
			for _, source := range []string{base, path} {
				if program, err := xlua.Compile(source); program != nil || err == nil || !strings.Contains(err.Error(), "loaded as a configuration file") {
					t.Fatalf("Compile(%q) = %v, %v; want config source rejection", source, program, err)
				}
			}
			if err := os.Rename(path, path+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("function HandleRoute() end"), 0o600); err != nil {
				t.Fatal(err)
			}
			if program, err := xlua.Compile(path); program != nil || err == nil || !strings.Contains(err.Error(), "loaded as a configuration file") {
				t.Fatalf("Compile = %v, %v; want replaced config path rejection", program, err)
			}
		})
	}
	path := filepath.Join(dir, "ordinary.lua")
	if err := os.WriteFile(path, []byte("function HandleRoute() end"), 0o600); err != nil {
		t.Fatal(err)
	}
	if program, err := xlua.Compile(path); err != nil || program == nil {
		t.Fatalf("ordinary script in the config directory must remain usable: %v", err)
	}
}

func testConfigHardLinkCannotRunAsLua(t *testing.T, dir string) {
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("null = 0\nfunction HandleRoute() end"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias.lua")
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := serial.BuildConfig([]*core.ConfigSource{{Name: path, Format: "json"}}); err != nil {
		t.Fatal(err)
	}
	if program, err := xlua.Compile(alias); program != nil || err == nil || !strings.Contains(err.Error(), "loaded as a configuration file") {
		t.Fatalf("Compile = %v, %v; want config hard link rejection", program, err)
	}
}

func testStdinConfigCannotRunAsLua(t *testing.T, dir string) {
	path := filepath.Join(dir, "config.lua")
	if err := os.WriteFile(path, []byte("null = 0\nfunction HandleRoute() end"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	originalStdin := os.Stdin
	os.Stdin = file
	t.Cleanup(func() {
		os.Stdin = originalStdin
		file.Close()
	})
	if _, err := serial.BuildConfig([]*core.ConfigSource{{Name: "stdin:", Format: "json"}}); err != nil {
		t.Fatal(err)
	}
	if program, err := xlua.Compile(path); program != nil || err == nil || !strings.Contains(err.Error(), "loaded as a configuration file") {
		t.Fatalf("Compile = %v, %v; want redirected config rejection", program, err)
	}
}
