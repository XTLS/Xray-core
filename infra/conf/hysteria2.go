package conf

import (
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/hysteria2"
	"google.golang.org/protobuf/proto"
)

type Hysteria2ClientConfig struct {
	Address *Address `json:"address"`
	Port    uint16   `json:"port"`
}

func (c *Hysteria2ClientConfig) Build() (proto.Message, error) {
	config := new(hysteria2.ClientConfig)

	config.Server = &protocol.ServerEndpoint{
		Address: c.Address.Build(),
		Port:    uint32(c.Port),
	}

	return config, nil
}
