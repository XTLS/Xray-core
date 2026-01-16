package conf

import (
	"github.com/xtls/xray-core/app/reverse"
	"google.golang.org/protobuf/proto"
)

type BridgeConfig struct {
	Tag    string `json:"tag"`
	Domain string `json:"domain"`
}

func (c *BridgeConfig) Build() (*reverse.BridgeConfig, error) {
	return &reverse.BridgeConfig{
		Tag:    c.Tag,
		Domain: c.Domain,
	}, nil
}

type PortalConfig struct {
	Tag              string `json:"tag"`
	Domain           string `json:"domain"`
	HeartbeatPeriod  uint32 `json:"heartbeatPeriod"`
	HeartbeatPadding uint32 `json:"heartbeatPadding"`
}

func (c *PortalConfig) Build() (*reverse.PortalConfig, error) {
	if c.HeartbeatPeriod == 0 {
		c.HeartbeatPeriod = 10
	}
	if c.HeartbeatPadding == 0 {
		c.HeartbeatPadding = 64
	}
	return &reverse.PortalConfig{
		Tag:              c.Tag,
		Domain:           c.Domain,
		HeartbeatPeriod:  c.HeartbeatPeriod,
		HeartbeatPadding: c.HeartbeatPadding,
	}, nil
}

type ReverseConfig struct {
	Bridges []BridgeConfig `json:"bridges"`
	Portals []PortalConfig `json:"portals"`
}

func (c *ReverseConfig) Build() (proto.Message, error) {
	config := &reverse.Config{}
	for _, bconfig := range c.Bridges {
		b, err := bconfig.Build()
		if err != nil {
			return nil, err
		}
		config.BridgeConfig = append(config.BridgeConfig, b)
	}

	for _, pconfig := range c.Portals {
		p, err := pconfig.Build()
		if err != nil {
			return nil, err
		}
		config.PortalConfig = append(config.PortalConfig, p)
	}

	return config, nil
}
