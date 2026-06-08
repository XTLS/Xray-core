package conf

import (
	"encoding/json"

	"github.com/xtls/xray-core/proxy/plugin"
	"google.golang.org/protobuf/proto"
)

type PluginOutboundConfig struct {
	Name   string           `json:"name"`
	Params *json.RawMessage `json:"params"`
}

func (c *PluginOutboundConfig) Build() (proto.Message, error) {
	var paramsStr string
	if c.Params != nil {
		paramsStr = string(*c.Params)
	}
	return &plugin.ClientConfig{
		Name:   c.Name,
		Params: paramsStr,
	}, nil
}
