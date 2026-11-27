package conf_test

import (
	"encoding/json"
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

func TestUDPIdle(t *testing.T) {
	pConf := new(Policy)
	common.Must(json.Unmarshal([]byte(`{"connIdle": 1800, "udpIdle": 300}`), pConf))
	p, err := pConf.Build()
	common.Must(err)
	if v := p.Timeout.UdpIdle.GetValue(); v != 300 {
		t.Error("expected UDP idle timeout 300 but got ", v)
	}

	if v := p.Timeout.ConnectionIdle.GetValue(); v != 1800 {
		t.Error("expected connection idle timeout 1800 but got ", v)
	}

	p, err = (&Policy{}).Build()
	common.Must(err)
	if p.Timeout.UdpIdle != nil {
		t.Error("expected no UDP idle timeout but got ", p.Timeout.UdpIdle.GetValue())
	}
}
