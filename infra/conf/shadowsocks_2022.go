package conf

import (
	"github.com/golang/protobuf/proto"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

type Shadowsocks2022ServerConfig struct {
	Cipher      string       `json:"method"`
	Key         string       `json:"key"`
	NetworkList *NetworkList `json:"network"`
}

func (v *Shadowsocks2022ServerConfig) Build() (proto.Message, error) {
	var network []net.Network
	if v.NetworkList != nil {
		network = v.NetworkList.Build()
	}
	return &shadowsocks_2022.ServerConfig{
		Method:  v.Cipher,
		Key:     v.Key,
		Network: network,
	}, nil
}

type Shadowsocks2022ClientConfig struct {
	Address              *Address `json:"address"`
	Port                 uint16   `json:"port"`
	Cipher               string   `json:"method"`
	Key                  string   `json:"key"`
	ReducedIvHeadEntropy bool     `json:"reducedIvHeadEntropy"`
}

func (v *Shadowsocks2022ClientConfig) Build() (proto.Message, error) {
	if v.Address == nil {
		return nil, newError("shadowsocks 2022: missing server address")
	}
	return &shadowsocks_2022.ClientConfig{
		Address:              v.Address.Build(),
		Port:                 uint32(v.Port),
		Method:               v.Cipher,
		Key:                  v.Key,
		ReducedIvHeadEntropy: v.ReducedIvHeadEntropy,
	}, nil
}
