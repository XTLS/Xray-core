package conf

import (
	"encoding/base64"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/proxy/freedom"
	"google.golang.org/protobuf/proto"
)

type ResponseConfig struct {
	Type               string `json:"type"`
	CustomResponseData string `json:"customResponseData"`
}

type BlackholeConfig struct {
	Response *ResponseConfig `json:"response"`
}

func (v *BlackholeConfig) Build() (proto.Message, error) {
	errors.PrintDeprecatedFeatureWarning(`"blackhole" outbound`, `"freedom" outbound with a blocking "firewall" rule`)
	rule := &freedom.FirewallConfig{
		Action:   freedom.RuleAction_Block,
		Delay:    &freedom.Range{},
		LogLevel: log.Severity_Unknown.Enum(),
	}
	if v.Response != nil {
		responseName := strings.ToLower(v.Response.Type)
		switch responseName {
		case "none", "":
			rule.Reply = &freedom.Reply{Type: "none"}
		case "http":
			rule.Reply = &freedom.Reply{Type: "http"}
		case "custom":
			data, err := base64.StdEncoding.DecodeString(v.Response.CustomResponseData)
			if err != nil {
				return nil, errors.New("failed to decode custom response data: " + err.Error())
			}
			rule.Reply = &freedom.Reply{Type: "custom", CustomResponseData: data}
		default:
			return nil, errors.New("unknown blackhole response: " + responseName)
		}
	}

	return &freedom.Config{Firewall: []*freedom.FirewallConfig{rule}}, nil
}
