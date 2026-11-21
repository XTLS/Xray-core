package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/splithttp"
)

func Test_SplitHTTP_PacketDown(t *testing.T) {
	rawJSON := `{
	  "path": "/sh",
	  "packetDown": { "keepAlive": true, "keepAlivePeriod": "5-10", "keepAliveLength": 32 }
	}`
	cfg := new(SplitHTTPConfig)
	if err := json.Unmarshal([]byte(rawJSON), cfg); err != nil {
		t.Fatal(err)
	}
	built, err := cfg.Build()
	if err != nil {
		t.Fatal(err)
	}

	pd := built.(*splithttp.Config).GetPacketDown()
	if pd == nil {
		t.Fatal("packetDown was not built")
	}
	if !pd.GetKeepAlive() {
		t.Error("packetDown.keepAlive should be true")
	}
	if r := cmp.Diff(int32(5), pd.GetKeepAlivePeriod().GetFrom()); r != "" {
		t.Error(r)
	}
	if r := cmp.Diff(int32(32), pd.GetKeepAliveLength().GetTo()); r != "" {
		t.Error(r)
	}
}

func Test_SplitHTTP_PacketDownNegative(t *testing.T) {
	rawJSON := `{ "path": "/sh", "packetDown": { "keepAlive": true, "keepAlivePeriod": "-1-10" } }`
	cfg := new(SplitHTTPConfig)
	parseErr := json.Unmarshal([]byte(rawJSON), cfg)
	_, buildErr := cfg.Build()
	if parseErr == nil && buildErr == nil {
		t.Error("expected negative period to fail at least one stage")
	}
}

func Test_SplitHTTP_PacketDownAbsent(t *testing.T) {
	rawJSON := `{ "path": "/sh" }`
	cfg := new(SplitHTTPConfig)
	if err := json.Unmarshal([]byte(rawJSON), cfg); err != nil {
		t.Fatal(err)
	}
	built, err := cfg.Build()
	if err != nil {
		t.Fatal(err)
	}
	if built.(*splithttp.Config).GetPacketDown() != nil {
		t.Error("packetDown should stay unset when absent")
	}
}
