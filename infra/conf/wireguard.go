package conf

import (
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/xtls/xray-core/proxy/wireguard"
	"google.golang.org/protobuf/proto"
)

type WireGuardPeerConfig struct {
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey"`
	Endpoint     string   `json:"endpoint"`
	KeepAlive    int      `json:"keepAlive"`
	AllowedIPs   []string `json:"allowedIPs,omitempty"`
}

func (c *WireGuardPeerConfig) Build() (proto.Message, error) {
	var err error
	config := new(wireguard.PeerConfig)

	config.PublicKey, err = parseWireGuardKey(c.PublicKey)
	if err != nil {
		return nil, err
	}

	if c.PreSharedKey != "" {
		config.PreSharedKey, err = parseWireGuardKey(c.PreSharedKey)
		if err != nil {
			return nil, err
		}
	} else {
		config.PreSharedKey = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	config.Endpoint = c.Endpoint
	// default 0
	config.KeepAlive = int32(c.KeepAlive)
	if c.AllowedIPs == nil {
		config.AllowedIps = []string{"0.0.0.0/0", "::0/0"}
	} else {
		config.AllowedIps = c.AllowedIPs
	}

	return config, nil
}

type WireGuardConfig struct {
	SecretKey      string                 `json:"secretKey"`
	Address        []string               `json:"address"`
	Peers          []*WireGuardPeerConfig `json:"peers"`
	MTU            int                    `json:"mtu"`
	NumWorkers     int                    `json:"workers"`
	Reserved       []byte                 `json:"reserved"`
	DomainStrategy string                 `json:"domainStrategy"`
}

func (c *WireGuardConfig) Build() (proto.Message, error) {
	config := new(wireguard.DeviceConfig)

	var err error
	config.SecretKey, err = parseWireGuardKey(c.SecretKey)
	if err != nil {
		return nil, err
	}

	if c.Address == nil {
		// bogon ips
		config.Endpoint = []string{"10.0.0.1", "fd59:7153:2388:b5fd:0000:0000:0000:0001"}
	} else {
		config.Endpoint = c.Address
	}

	if c.Peers != nil {
		config.Peers = make([]*wireguard.PeerConfig, len(c.Peers))
		for i, p := range c.Peers {
			msg, err := p.Build()
			if err != nil {
				return nil, err
			}
			config.Peers[i] = msg.(*wireguard.PeerConfig)
		}
	}

	if c.MTU == 0 {
		config.Mtu = 1420
	} else {
		config.Mtu = int32(c.MTU)
	}
	// these a fallback code exists in github.com/nanoda0523/wireguard-go code,
	// we don't need to process fallback manually
	config.NumWorkers = int32(c.NumWorkers)

	if len(c.Reserved) != 0 && len(c.Reserved) != 3 {
		return nil, newError(`"reserved" should be empty or 3 bytes`)
	}
	config.Reserved = c.Reserved

	config.DomainStrategy = wireguard.DeviceConfig_FORCE_IP
	switch strings.ToLower(c.DomainStrategy) {
	case "forceip4", "forceipv4", "force_ip4", "force_ipv4", "force_ip_v4", "force-ip4", "force-ipv4", "force-ip-v4":
		config.DomainStrategy = wireguard.DeviceConfig_FORCE_IP4
	case "forceip6", "forceipv6", "force_ip6", "force_ipv6", "force_ip_v6", "force-ip6", "force-ipv6", "force-ip-v6":
		config.DomainStrategy = wireguard.DeviceConfig_FORCE_IP6
	case "forceip46", "forceipv4v6", "force_ip46", "force_ipv4v6", "force_ip_v4v6", "force-ip46", "force-ipv4v6", "force-ip-v4v6":
		config.DomainStrategy = wireguard.DeviceConfig_FORCE_IP46
	case "forceip64", "forceipv6v4", "force_ip64", "force_ipv6v4", "force_ip_v6v4", "force-ip64", "force-ipv6v4", "force-ip-v6v4":
		config.DomainStrategy = wireguard.DeviceConfig_FORCE_IP64
	}

	return config, nil
}

func parseWireGuardKey(str string) (string, error) {
	if len(str) != 64 {
		// may in base64 form
		dat, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			return "", err
		}
		if len(dat) != 32 {
			return "", newError("key should be 32 bytes: " + str)
		}
		return hex.EncodeToString(dat), err
	} else {
		// already hex form
		return str, nil
	}
}
