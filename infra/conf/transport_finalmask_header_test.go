package conf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/transport/internet/finalmask/header/custom"
)

const headerScript = `function HandleHeader(stream, address, role) end
`

func writeHeaderScript(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "header.lua")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHeaderScript(t *testing.T) {
	path := writeHeaderScript(t, headerScript)

	tcp, err := (&HeaderCustomTCP{Script: path}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if got := tcp.(*custom.TCPConfig).Script; got != path {
		t.Errorf("got script %q, want the path", got)
	}

	udp, err := (&HeaderCustomUDP{Script: path}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if got := udp.(*custom.UDPConfig).Script; got != path {
		t.Errorf("got script %q, want the path", got)
	}
}

func TestHeaderScriptRejected(t *testing.T) {
	path := writeHeaderScript(t, headerScript)
	invalid := writeHeaderScript(t, "function HandleHeader(")

	for name, mask := range map[string]Buildable{
		"tcp script with clients": &HeaderCustomTCP{Script: path, Clients: [][]TCPItem{{{Rand: 2}}}},
		"tcp script is not lua":   &HeaderCustomTCP{Script: invalid},
		"tcp script is missing":   &HeaderCustomTCP{Script: filepath.Join(t.TempDir(), "absent.lua")},
		"udp script with client":  &HeaderCustomUDP{Script: path, Client: []UDPItem{{Rand: 2}}},
		"udp script standalone":   &HeaderCustomUDP{Script: path, Mode: "standalone"},
		"udp script is not lua":   &HeaderCustomUDP{Script: invalid},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := mask.Build(); err == nil {
				t.Error("expected an error")
			}
		})
	}
}
