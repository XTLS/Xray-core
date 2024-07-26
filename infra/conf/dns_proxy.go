package conf

import (
	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/proxy/dns"
	"google.golang.org/protobuf/proto"
)

type DNSOutboundConfig struct {
	Network    Network  `json:"network"`
	Address    *Address `json:"address"`
	Port       uint16   `json:"port"`
	UserLevel  uint32   `json:"userLevel"`
	NonIPQuery string   `json:"nonIPQuery"`
}

func (c *DNSOutboundConfig) Build() (proto.Message, error) {
	config := &dns.Config{
		Server: &net.Endpoint{
			Network: c.Network.Build(),
			Port:    uint32(c.Port),
		},
		UserLevel: c.UserLevel,
	}
	if c.Address != nil {
		config.Server.Address = c.Address.Build()
	}
	switch c.NonIPQuery {
	case "":
		c.NonIPQuery = "drop"
	case "drop", "skip":
	default:
		return nil, errors.New(`unknown "nonIPQuery": `, c.NonIPQuery)
	}
	config.Non_IPQuery = c.NonIPQuery
	return config, nil
}
