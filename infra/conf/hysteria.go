package conf

import (
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/hysteria"
	"google.golang.org/protobuf/proto"
)

type HysteriaClientConfig struct {
	Address *Address `json:"address"`
	Port    uint16   `json:"port"`
}

func (c *HysteriaClientConfig) Build() (proto.Message, error) {
	config := new(hysteria.ClientConfig)

	config.Server = &protocol.ServerEndpoint{
		Address: c.Address.Build(),
		Port:    uint32(c.Port),
	}

	return config, nil
}
