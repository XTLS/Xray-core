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
	var paramsBytes []byte
	if c.Params != nil {
		paramsBytes = []byte(*c.Params)
	}
	return &plugin.ClientConfig{
		Name:   c.Name,
		Params: paramsBytes,
	}, nil
}
