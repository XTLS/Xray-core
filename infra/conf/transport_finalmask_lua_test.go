package conf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/xtls/xray-core/transport/internet/finalmask/lua"
)

const luaMaskScript = `function HandleNoise(plan, address, role) plan:Add("n") end
`

func writeLuaMaskScript(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mask.lua")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLuaMask(t *testing.T) {
	path := writeLuaMaskScript(t, luaMaskScript)
	msg, err := (&LuaMask{Script: path, Reset: Int32Range{From: 30, To: 60}}).Build()
	if err != nil {
		t.Fatal(err)
	}
	cfg := msg.(*lua.Config)
	if cfg.Script != path {
		t.Errorf("got script %q, want the path", cfg.Script)
	}
	if cfg.ResetMin != 30 || cfg.ResetMax != 60 {
		t.Errorf("got reset %d-%d, want 30-60", cfg.ResetMin, cfg.ResetMax)
	}
}

func TestLuaMaskFromJSON(t *testing.T) {
	path := writeLuaMaskScript(t, luaMaskScript)
	settings := json.RawMessage(`{"script": ` + strconv.Quote(path) + `, "reset": "30-60"}`)
	mask := Mask{Type: "lua", Settings: &settings}

	for name, tcp := range map[string]bool{"tcp": true, "udp": false} {
		t.Run(name, func(t *testing.T) {
			msg, err := mask.Build(tcp)
			if err != nil {
				t.Fatal(err)
			}
			if cfg, ok := msg.(*lua.Config); !ok || cfg.Script != path {
				t.Errorf("got %T %+v", msg, msg)
			}
		})
	}
}

func TestLuaMaskRejected(t *testing.T) {
	for name, mask := range map[string]*LuaMask{
		"no script":    {},
		"missing file": {Script: filepath.Join(t.TempDir(), "absent.lua")},
		"not lua":      {Script: writeLuaMaskScript(t, "function HandleNoise(")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := mask.Build(); err == nil {
				t.Error("expected an error")
			}
		})
	}
}
