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
	switch strings.ToLower(c.DomainStrategy) {
	case "asis", "":
		config.DomainStrategy = freedom.Config_AS_IS
	case "useip":
		config.DomainStrategy = freedom.Config_USE_IP
	case "useipv4":
		config.DomainStrategy = freedom.Config_USE_IP4
	case "useipv6":
		config.DomainStrategy = freedom.Config_USE_IP6
	case "useipv4v6":
		config.DomainStrategy = freedom.Config_USE_IP46
	case "useipv6v4":
		config.DomainStrategy = freedom.Config_USE_IP64
	case "forceip":
		config.DomainStrategy = freedom.Config_FORCE_IP
	case "forceipv4":
		config.DomainStrategy = freedom.Config_FORCE_IP4
	case "forceipv6":
		config.DomainStrategy = freedom.Config_FORCE_IP6
	case "forceipv4v6":
		config.DomainStrategy = freedom.Config_FORCE_IP46
	case "forceipv6v4":
		config.DomainStrategy = freedom.Config_FORCE_IP64
	default:
		return nil, newError("unsupported domain strategy: ", c.DomainStrategy)
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
