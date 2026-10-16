package geodata

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	commongeodata "github.com/xtls/xray-core/common/geodata"
	xlua "github.com/xtls/xray-core/common/lua"
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
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			d := &downloader{ctx: context.Background(), httpClient: server.Client()}
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
