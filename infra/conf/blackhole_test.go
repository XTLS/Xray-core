package conf_test

import (
	"testing"

	"github.com/xtls/xray-core/v1/common/serial"
	. "github.com/xtls/xray-core/v1/infra/conf"
	"github.com/xtls/xray-core/v1/proxy/blackhole"
)

func TestHTTPResponseJSON(t *testing.T) {
	creator := func() Buildable {
		return new(BlackholeConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"response": {
					"type": "http"
				}
			}`,
			Parser: loadJSON(creator),
			Output: &blackhole.Config{
				Response: serial.ToTypedMessage(&blackhole.HTTPResponse{}),
			},
		},
		{
			Input:  `{}`,
			Parser: loadJSON(creator),
			Output: &blackhole.Config{},
		},
	})
}
