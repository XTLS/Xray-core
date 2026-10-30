package geodata

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	commongeodata "github.com/xtls/xray-core/common/geodata"
	xlua "github.com/xtls/xray-core/common/lua"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/yuin/gopher-lua/parse"
	"google.golang.org/protobuf/proto"
)

func TestDownloadOneLuaGuard(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		code string
	}{
		{"geodata", "\x0a\x03\x0a\x01A", "A"},
		{"prefixed geodata", luaGuardHeader + "\x0a\x03\x0a\x01A", "A"},
		{"Lua", "function HandleRoute() end", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("xray.location.asset", dir)
			if err := os.WriteFile(filepath.Join(dir, "asset.lua"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			d := &downloader{ctx: context.Background(), httpsClient: server.Client()}
			staged, err := d.downloadOne(&Asset{Url: server.URL, File: "asset.lua"})
			if err != nil {
				t.Fatal(err)
			}
			tx, err := swapAll([]stage{staged})
			if err != nil {
				t.Fatal(err)
			}
			if err := tx.commit(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(staged.target)
			if err != nil || string(data) != luaGuardHeader+tc.body {
				t.Fatalf("downloaded data = % x, %v", data, err)
			}
			program, err := xlua.Compile(staged.target)
			var syntaxErr *parse.Error
			if program != nil || !errors.As(err, &syntaxErr) || syntaxErr.Pos.Line != 1 || syntaxErr.Pos.Column != 1 {
				t.Fatalf("want Lua rejection at the first byte, got %v, %v", program, err)
			}
			if tc.code != "" {
				var list commongeodata.GeoSiteList
				if err := proto.Unmarshal(data, &list); err != nil {
					t.Fatal(err)
				}
				if len(list.Entry) != 1 || list.Entry[0].Code != tc.code {
					t.Fatalf("header changed geodata: %v", &list)
				}
				if _, err := commongeodata.ParseDomainRules([]string{"ext:" + filepath.Base(staged.target) + ":" + tc.code}, commongeodata.Domain_Full); err != nil {
					t.Fatalf("geodata loader rejected the header: %v", err)
				}
			}
		})
	}
}

func TestProtobufConfigValidation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("xray.location.asset", dir)
	for _, name := range []string{"asset.dat", "asset.DAT"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "directory.dat"), 0o700); err != nil {
		t.Fatal(err)
	}
	server, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	for _, tc := range []struct {
		name      string
		config    *Config
		wantError string
	}{
		{"minutely cron", &Config{Cron: "* * * * *"}, ""},
		{"minimum interval", &Config{Cron: "@every 1m"}, ""},
		{"short interval", &Config{Cron: "@every 59s"}, "interval must be at least 1 minute"},
		{"fractional interval", &Config{Cron: "@every 59.999s"}, "interval must be at least 1 minute"},
		{"invalid cron", &Config{Cron: "invalid"}, "invalid geodata cron"},
		{"dat extension", &Config{Cron: "@daily", Assets: []*Asset{{Url: "https://example.com/asset.dat", File: "asset.dat"}}}, ""},
		{"uppercase extension", &Config{Cron: "@daily", Assets: []*Asset{{Url: "https://example.com/asset.dat", File: "asset.DAT"}}}, ""},
		{"invalid extension", &Config{Cron: "@daily", Assets: []*Asset{{Url: "https://example.com/asset.dat", File: "asset.lua"}}}, "extension must be .dat"},
		{"missing extension", &Config{Cron: "@daily", Assets: []*Asset{{Url: "https://example.com/asset.dat", File: "asset"}}}, "extension must be .dat"},
		{"missing file", &Config{Cron: "@daily", Assets: []*Asset{{Url: "https://example.com/asset.dat", File: "missing.dat"}}}, "invalid geodata asset file"},
		{"directory", &Config{Cron: "@daily", Assets: []*Asset{{Url: "https://example.com/asset.dat", File: "directory.dat"}}}, "asset is not a regular file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, err := serial.ToTypedMessage(tc.config).GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			_, err = core.CreateObject(server, config)
			if tc.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("CreateObject() error = %v; want %q", err, tc.wantError)
			}
		})
	}
}
