package conf_test

import (
	"testing"

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
				Response: &blackhole.Response{Type: "http"},
			},
		},
		{
			Input:  `{}`,
			Parser: loadJSON(creator),
			Output: &blackhole.Config{},
		},
	})
}

func TestCustomResponseJSON(t *testing.T) {
	creator := func() Buildable {
		return new(BlackholeConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"response": {
					"type": "custom",
					"customResponseData": "Y3VzdG9tIHJlc3BvbnNl"
				}
			}`,
			Parser: loadJSON(creator),
			Output: &blackhole.Config{
				Response: &blackhole.Response{
					Type:               "custom",
					CustomResponseData: []byte("custom response"),
				},
			},
		},
	})
}
