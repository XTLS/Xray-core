package conf

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/transport/internet/finalmask/udphop"
)

func TestUDPHopBuildInterval(t *testing.T) {
	for _, c := range []struct {
		settings string
		min, max int64
		ok       bool
	}{
		{`{"mode": "intervalRemote", "remotePorts": "20000-20010"}`, 30, 30, true},
		{`{"mode": "intervalRemote", "remotePorts": "20000-20010", "interval": "5-10"}`, 5, 10, true},
		{`{"mode": "intervalRemote", "remotePorts": "20000-20010", "interval": 60}`, 60, 60, true},
		{`{"mode": "intervalRemote", "remotePorts": "20000-20010", "interval": "2-3"}`, 0, 0, false},
		{`{"mode": "intervalRemote", "remotePorts": "20000-20010", "interval": "4-10"}`, 0, 0, false},
	} {
		hop := new(UDPHop)
		if err := json.Unmarshal([]byte(c.settings), hop); err != nil {
			t.Fatal(err)
		}
		built, err := hop.Build()
		if !c.ok {
			if err == nil {
				t.Errorf("expected an error for %s", c.settings)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", c.settings, err)
		}
		config := built.(*udphop.Config)
		if config.IntervalMin != c.min || config.IntervalMax != c.max {
			t.Errorf("%s: interval %d-%d, want %d-%d", c.settings, config.IntervalMin, config.IntervalMax, c.min, c.max)
		}
	}
}
