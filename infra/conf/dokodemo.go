package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"google.golang.org/protobuf/proto"
)

type DokodemoConfig struct {
	Address        *Address          `json:"address"`
	ToAddress      *Address          `json:"toAddress"`
	Port           uint16            `json:"port"`
	ToPort         uint16            `json:"toPort"`
	PortMap        map[string]string `json:"portMap"`
	Network        *NetworkList      `json:"network"`
	AllowedNetwork *NetworkList      `json:"allowedNetwork"`
	FollowRedirect bool              `json:"followRedirect"`
	UserLevel      uint32            `json:"userLevel"`
}

func (v *DokodemoConfig) Build() (proto.Message, error) {
	if v.Address != nil {
		errors.PrintDeprecatedFeatureWarning(`"address"`, `"toAddress"`)
		v.ToAddress = v.Address
	}
	if v.Port != 0 {
		errors.PrintDeprecatedFeatureWarning(`"port"`, `"toPort"`)
		v.ToPort = v.Port
	}
	if v.Network != nil {
		errors.PrintDeprecatedFeatureWarning(`"network"`, `"allowedNetwork"`)
		v.AllowedNetwork = v.Network
	}
	config := new(dokodemo.Config)
	if v.ToAddress != nil {
		config.ToAddress = v.ToAddress.Build()
	}
	config.ToPort = uint32(v.ToPort)
	config.PortMap = v.PortMap
	for _, v := range config.PortMap {
		if _, _, err := net.SplitHostPort(v); err != nil {
			return nil, errors.New("invalid portMap: ", v).Base(err)
		}
	}
	config.AllowedNetworks = v.AllowedNetwork.Build()
	config.FollowRedirect = v.FollowRedirect
	config.UserLevel = v.UserLevel
	return config, nil
}
