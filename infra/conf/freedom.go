package conf

import (
	"net"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	v2net "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

type FreedomConfig struct {
	TargetStrategy string    `json:"targetStrategy"`
	DomainStrategy string    `json:"domainStrategy"`
	Redirect       string    `json:"redirect"`
	UserLevel      uint32    `json:"userLevel"`
	Fragment       *Fragment `json:"fragment"`
	Noise          *Noise    `json:"noise"`
	Noises         []*Noise  `json:"noises"`
	ProxyProtocol  uint32    `json:"proxyProtocol"`
}

func (c *FreedomConfig) Build() (proto.Message, error) {
	config := new(freedom.Config)
	targetStrategy := c.TargetStrategy
	if targetStrategy == "" {
		targetStrategy = c.DomainStrategy
	}
	switch strings.ToLower(targetStrategy) {
	case "asis", "":
		config.DomainStrategy = internet.DomainStrategy_AS_IS
	case "useip":
		config.DomainStrategy = internet.DomainStrategy_USE_IP
	case "useipv4":
		config.DomainStrategy = internet.DomainStrategy_USE_IP4
	case "useipv6":
		config.DomainStrategy = internet.DomainStrategy_USE_IP6
	case "useipv4v6":
		config.DomainStrategy = internet.DomainStrategy_USE_IP46
	case "useipv6v4":
		config.DomainStrategy = internet.DomainStrategy_USE_IP64
	case "forceip":
		config.DomainStrategy = internet.DomainStrategy_FORCE_IP
	case "forceipv4":
		config.DomainStrategy = internet.DomainStrategy_FORCE_IP4
	case "forceipv6":
		config.DomainStrategy = internet.DomainStrategy_FORCE_IP6
	case "forceipv4v6":
		config.DomainStrategy = internet.DomainStrategy_FORCE_IP46
	case "forceipv6v4":
		config.DomainStrategy = internet.DomainStrategy_FORCE_IP64
	default:
		return nil, errors.New("unsupported domain strategy: ", targetStrategy)
	}

	if c.Fragment != nil {
		return nil, errors.PrintRemovedFeatureError("fragment", "finalmask/tcp fragment")
	}

	if c.Noise != nil {
		return nil, errors.PrintRemovedFeatureError("noise", "finalmask/udp noise")
	}

	if c.Noises != nil {
		return nil, errors.PrintRemovedFeatureError("noise", "finalmask/udp noise")
	}

	config.UserLevel = c.UserLevel
	if len(c.Redirect) > 0 {
		host, portStr, err := net.SplitHostPort(c.Redirect)
		if err != nil {
			return nil, errors.New("invalid redirect address: ", c.Redirect, ": ", err).Base(err)
		}
		port, err := v2net.PortFromString(portStr)
		if err != nil {
			return nil, errors.New("invalid redirect port: ", c.Redirect, ": ", err).Base(err)
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
	if c.ProxyProtocol > 0 && c.ProxyProtocol <= 2 {
		config.ProxyProtocol = c.ProxyProtocol
	}
	return config, nil
}
