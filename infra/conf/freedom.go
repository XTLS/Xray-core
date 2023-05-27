package conf

import (
	"net"
	"strconv"
	"strings"

	"github.com/golang/protobuf/proto"
	v2net "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/freedom"
)

type FreedomConfig struct {
	DomainStrategy string    `json:"domainStrategy"`
	Timeout        *uint32   `json:"timeout"`
	Redirect       string    `json:"redirect"`
	UserLevel      uint32    `json:"userLevel"`
	Fragment       *Fragment `json:"fragment"`
}

type Fragment struct {
	Packets  string `json:"packets"`
	Length   string `json:"length"`
	Interval string `json:"interval"`
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
	}

	if c.Fragment != nil {
		if len(c.Fragment.Interval) == 0 || len(c.Fragment.Length) == 0 {
			return nil, newError("Invalid interval or length")
		}
		intervalMinMax := strings.Split(c.Fragment.Interval, "-")
		var minInterval, maxInterval int64
		var err, err2 error
		if len(intervalMinMax) == 2 {
			minInterval, err = strconv.ParseInt(intervalMinMax[0], 10, 64)
			maxInterval, err2 = strconv.ParseInt(intervalMinMax[1], 10, 64)
		} else {
			minInterval, err = strconv.ParseInt(intervalMinMax[0], 10, 64)
			maxInterval = minInterval
		}
		if err != nil {
			return nil, newError("Invalid minimum interval: ", err).Base(err)
		}
		if err2 != nil {
			return nil, newError("Invalid maximum interval: ", err2).Base(err2)
		}

		lengthMinMax := strings.Split(c.Fragment.Length, "-")
		var minLength, maxLength int64
		if len(lengthMinMax) == 2 {
			minLength, err = strconv.ParseInt(lengthMinMax[0], 10, 64)
			maxLength, err2 = strconv.ParseInt(lengthMinMax[1], 10, 64)

		} else {
			minLength, err = strconv.ParseInt(lengthMinMax[0], 10, 64)
			maxLength = minLength
		}
		if err != nil {
			return nil, newError("Invalid minimum length: ", err).Base(err)
		}
		if err2 != nil {
			return nil, newError("Invalid maximum length: ", err2).Base(err2)
		}

		if minInterval > maxInterval {
			minInterval, maxInterval = maxInterval, minInterval
		}
		if minLength > maxLength {
			minLength, maxLength = maxLength, minLength
		}

		config.Fragment = &freedom.Fragment{
			MinInterval: int32(minInterval),
			MaxInterval: int32(maxInterval),
			MinLength:   int32(minLength),
			MaxLength:   int32(maxLength),
		}

		if len(c.Fragment.Packets) > 0 {
			packetRange := strings.Split(c.Fragment.Packets, "-")
			var startPacket, endPacket int64
			if len(packetRange) == 2 {
				startPacket, err = strconv.ParseInt(packetRange[0], 10, 64)
				endPacket, err2 = strconv.ParseInt(packetRange[1], 10, 64)
			} else {
				startPacket, err = strconv.ParseInt(packetRange[0], 10, 64)
				endPacket = startPacket
			}
			if err != nil {
				return nil, newError("Invalid start packet: ", err).Base(err)
			}
			if err2 != nil {
				return nil, newError("Invalid end packet: ", err2).Base(err2)
			}
			if startPacket > endPacket {
				return nil, newError("Invalid packet range: ", c.Fragment.Packets)
			}
			if startPacket < 1 {
				return nil, newError("Cannot start from packet 0")
			}
			config.Fragment.StartPacket = int32(startPacket)
			config.Fragment.EndPacket = int32(endPacket)
		} else {
			config.Fragment.StartPacket = 0
			config.Fragment.EndPacket = 0
		}
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
