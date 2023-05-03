package conf

import (
	"net"
	"strings"

	"github.com/golang/protobuf/proto"
	v2net "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/freedom"
)

type FreedomConfig struct {
	DomainStrategy string  `json:"domainStrategy"`
	Timeout        *uint32 `json:"timeout"`
	Redirect       string  `json:"redirect"`
	UserLevel      uint32  `json:"userLevel"`
}

// Build implements Buildable
func (c *FreedomConfig) Build() (proto.Message, error) {
	config := new(freedom.Config)
	config.DomainStrategy = freedom.Config_AS_IS
	switch strings.ToLower(c.DomainStrategy) {
	case "useip", "use_ip", "use-ip":
		config.DomainStrategy = freedom.Config_USE_IP
	case "useip4", "useipv4", "use_ip4", "use_ipv4", "use_ip_v4", "use-ip4", "use-ipv4", "use-ip-v4":
		config.DomainStrategy = freedom.Config_USE_IP4
	case "useip6", "useipv6", "use_ip6", "use_ipv6", "use_ip_v6", "use-ip6", "use-ipv6", "use-ip-v6":
		config.DomainStrategy = freedom.Config_USE_IP6
	case "useip46", "useipv4v6", "use_ip46", "use_ipv4v6":
		config.DomainStrategy = freedom.Config_USE_IP46
	case "useip64", "useipv6v4", "use_ip64", "use_ipv6v4":
		config.DomainStrategy = freedom.Config_USE_IP64
	case "forceip", "force_ip":
		config.DomainStrategy = freedom.Config_FORCE_IP
	case "forceip4", "forceipv4", "force_ip4", "force_ipv4":
		config.DomainStrategy = freedom.Config_FORCE_IP4
	case "forceip6", "forceipv6", "force_ip6", "force_ipv6":
		config.DomainStrategy = freedom.Config_FORCE_IP6
	case "forceip46", "forceipv4v6", "force_ip46", "force_ipv4v6":
		config.DomainStrategy = freedom.Config_FORCE_IP46
	case "forceip64", "forceipv6v4", "force_ip64", "force_ipv6v4":
		config.DomainStrategy = freedom.Config_FORCE_IP64
	}

	if c.Timeout != nil {
		config.Timeout = *c.Timeout
	}
	config.UserLevel = c.UserLevel
	if len(c.Redirect) > 0 {
		host, portStr, err := net.SplitHostPort(c.Redirect)
		if err != nil {
			return nil, newError("invalid redirect address: ", c.Redirect, ": ", err).Base(err)
		}
		port, err := v2net.PortFromString(portStr)
		if err != nil {
			return nil, newError("invalid redirect port: ", c.Redirect, ": ", err).Base(err)
		}
		config.DestinationOverride = &freedom.DestinationOverride{
			Server: &protocol.ServerEndpoint{
				Port: uint32(port),
			},
		}

		if len(host) > 0 {
			config.DestinationOverride.Server.Address = v2net.NewIPOrDomain(v2net.ParseAddress(host))
		}
	}
	return config, nil
}
