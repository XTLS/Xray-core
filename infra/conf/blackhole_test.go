package conf_test

import (
	"testing"

	"github.com/xtls/xray-core/common/serial"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/blackhole"
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
		{
			Input: `{
				"response": {
					"type": "http",
					"statusCode": 204
				}
			}`,
			Parser: loadJSON(creator),
			Output: &blackhole.Config{
				Response: serial.ToTypedMessage(&blackhole.HTTPResponse{StatusCode: 204}),
			},
		},
		{
			Input: `{
				"response": {
					"type": "http",
					"statusCode": 404
				}
			}`,
			Parser: loadJSON(creator),
			Output: &blackhole.Config{
				Response: serial.ToTypedMessage(&blackhole.HTTPResponse{StatusCode: 404}),
			},
		},
	})
}
