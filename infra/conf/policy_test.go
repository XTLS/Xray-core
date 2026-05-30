package conf_test

import (
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/infra/conf"
)

func TestBufferSize(t *testing.T) {
	cases := []struct {
		Input  int32
		Output int32
	}{
		{
			Input:  0,
			Output: 0,
		},
		{
			Input:  -1,
			Output: -1,
		},
		{
			Input:  1,
			Output: 1024,
		},
	}

	for _, c := range cases {
		bs := c.Input
		pConf := Policy{
			BufferSize: &bs,
		}
		p, err := pConf.Build()
		common.Must(err)
		if p.Buffer.Connection != c.Output {
			t.Error("expected buffer size ", c.Output, " but got ", p.Buffer.Connection)
		}
	}
}

// TestStatsUserInboundFlags guards the JSON->proto bridge for the
// per-user-per-inbound stat policy flags: a JSON policy carrying
// statsUserInbound{Uplink,Downlink} must produce a proto Policy whose Stats
// reflects them. Without this mapping the node's flags are silently dropped
// and no per-user-per-inbound counters are ever created.
func TestStatsUserInboundFlags(t *testing.T) {
	pConf := Policy{
		StatsUserInboundUplink:   true,
		StatsUserInboundDownlink: true,
	}
	p, err := pConf.Build()
	common.Must(err)
	if !p.Stats.UserInboundUplink {
		t.Error("expected UserInboundUplink to be true")
	}
	if !p.Stats.UserInboundDownlink {
		t.Error("expected UserInboundDownlink to be true")
	}

	// Defaults must be false so the feature stays off unless explicitly enabled.
	defConf := Policy{}
	def, err := defConf.Build()
	common.Must(err)
	if def.Stats.UserInboundUplink || def.Stats.UserInboundDownlink {
		t.Error("expected per-user-per-inbound flags to default to false")
	}
}
