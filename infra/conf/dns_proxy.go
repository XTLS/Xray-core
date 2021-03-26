package conf

import (
	"github.com/golang/protobuf/proto"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf/common"
	"github.com/xtls/xray-core/proxy/dns"
)

type DNSOutboundConfig struct {
	Network common.Network  `json:"network"`
	Address *common.Address `json:"address"`
	Port    uint16          `json:"port"`
}

func (c *DNSOutboundConfig) Build() (proto.Message, error) {
	config := &dns.Config{
		Server: &net.Endpoint{
			Network: c.Network.Build(),
			Port:    uint32(c.Port),
		},
	}
	if c.Address != nil {
		config.Server.Address = c.Address.Build()
	}
	return config, nil
}
