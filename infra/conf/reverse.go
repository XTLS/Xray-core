package conf

import (
	"github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/common/errors"
	"google.golang.org/protobuf/proto"
)

type BridgeConfig struct {
	Tag            string `json:"tag"`
	Domain         string `json:"domain"`
	MaxConcurrency uint32 `json:"maxConcurrency"`
	MaxConnections uint32 `json:"maxConnections"`
}

func (c *BridgeConfig) Build() (*reverse.BridgeConfig, error) {
	if c.MaxConnections > 0 && c.MaxConcurrency > 0 {
		return nil, errors.New("maxConnections cannot be specified together with maxConcurrency")
	}
	if c.MaxConnections == 0 && c.MaxConcurrency == 0 {
		c.MaxConcurrency = 16
	}
	return &reverse.BridgeConfig{
		Tag:            c.Tag,
		Domain:         c.Domain,
		MaxConcurrency: c.MaxConcurrency,
		MaxConnections: c.MaxConnections,
	}, nil
}

type PortalConfig struct {
	Tag    string `json:"tag"`
	Domain string `json:"domain"`
}

func (c *PortalConfig) Build() (*reverse.PortalConfig, error) {
	return &reverse.PortalConfig{
		Tag:    c.Tag,
		Domain: c.Domain,
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
