package conf

import (
	"strings"

	"github.com/xtls/xray-core/common/errors"
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
	if v.Response != nil {
		switch strings.ToLower(v.Response.Type) {
		case "none", "":
		default:
			errors.PrintDeprecatedFeatureWarning(`"blackhole" outbound response`, `the "responder" outbound`)
			return (&ResponderConfig{Type: v.Response.Type, Response: v.Response.CustomResponseData}).Build()
		}
	}

	return &freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Block}}}, nil
}
