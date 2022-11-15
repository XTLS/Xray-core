package conf

import (
	"encoding/base64"
	"encoding/hex"

	"github.com/golang/protobuf/proto"
	"github.com/xtls/xray-core/proxy/wireguard"
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
	SecretKey string                 `json:"secretKey"`
	Address   []string               `json:"address"`
	Peers     []*WireGuardPeerConfig `json:"peers"`
	MTU       int                    `json:"mtu"`
}

func (c *WireGuardConfig) Build() (proto.Message, error) {
	config := new(wireguard.DeviceConfig)

	var err error
	config.SecretKey, err = parseWireGuardKey(c.SecretKey)
	if err != nil {
		return nil, err
	}

	config.Endpoint = c.Address
	if config.Endpoint == nil {
		return nil, newError("no available addresses")
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

	return config, nil
}

func parseWireGuardKey(str string) (string, error) {
	if len(str) != 32 {
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
