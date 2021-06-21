package conf

import (
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/dns"
)

type DNSOutboundConfig struct {
	Network        Network  `json:"network"`
	Address        *Address `json:"address"`
	Port           uint16   `json:"port"`
	DomainStrategy string   `json:"domainStrategy"`
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
	config.DomainStrategy = dns.Config_USE_ALL
	switch strings.ToLower(c.DomainStrategy) {
	case "useip", "use_ip", "use-ip":
		config.DomainStrategy = dns.Config_USE_IP
	case "fake", "fakedns":
		config.DomainStrategy = dns.Config_USE_FAKE
	}
	return config, nil
}
