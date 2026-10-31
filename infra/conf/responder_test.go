package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/responder"
	"google.golang.org/protobuf/proto"
)

func TestResponderConfig(t *testing.T) {
	parser := loadJSON(func() Buildable { return new(ResponderConfig) })
	httpResponse := []byte("HTTP/1.1 403 Forbidden\r\n" +
		"Cache-Control: max-age=3600, public\r\n" +
		"Connection: close\r\n" +
		"Content-Length: 0\r\n\r\n")

	runMultiTestCase(t, []TestCase{
		{Input: `{"type":"http"}`, Parser: parser, Output: &responder.Config{Response: httpResponse}},
		{Input: `{"type":"HtTp"}`, Parser: parser, Output: &responder.Config{Response: httpResponse}},
		{Input: `{"type":"custom","response":"aGVsbG8="}`, Parser: parser, Output: &responder.Config{Response: []byte("hello")}},
		{Input: `{"type":"CuStOm","response":"aGVsbG8="}`, Parser: parser, Output: &responder.Config{Response: []byte("hello")}},
		{Input: `{"type":"custom","response":"AP+A"}`, Parser: parser, Output: &responder.Config{Response: []byte{0, 255, 128}}},
		{Input: `{"type":"custom","response":""}`, Parser: parser, Output: &responder.Config{}},
		{Input: `{"type":"custom"}`, Parser: parser, Output: &responder.Config{}},
		{
			Input: `{
				"protocol": "ReSpOnDeR",
				"tag": "reply",
				"settings": {"type": "custom", "response": "aGVsbG8="}
			}`,
			Parser: func(s string) (proto.Message, error) {
				var config OutboundDetourConfig
				if err := json.Unmarshal([]byte(s), &config); err != nil {
					return nil, err
				}
				return config.Build()
			},
			Output: &core.OutboundHandlerConfig{
				Tag:            "reply",
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}),
				ProxySettings:  serial.ToTypedMessage(&responder.Config{Response: []byte("hello")}),
			},
		},
	})
}

func TestResponderConfigErrors(t *testing.T) {
	parser := loadJSON(func() Buildable { return new(ResponderConfig) })
	for _, input := range []string{
		`{}`,
		`{"type":""}`,
		`{"type":"unknown"}`,
		`{"type":"none"}`,
		`{"type":"custom","response":"!"}`,
	} {
		if _, err := parser(input); err == nil {
			t.Fatalf("expected error for %s", input)
		}
	}
}
