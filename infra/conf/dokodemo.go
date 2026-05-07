package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"google.golang.org/protobuf/proto"
)

type DokodemoConfig struct {
	Address        *Address          `json:"address"`
	RewriteAddress *Address          `json:"rewriteAddress"`
	Port           uint16            `json:"port"`
	RewritePort    uint16            `json:"rewritePort"`
	PortMap        map[string]string `json:"portMap"`
	Network        *NetworkList      `json:"network"`
	AllowedNetwork *NetworkList      `json:"allowedNetwork"`
	FollowRedirect bool              `json:"followRedirect"`
	UserLevel      uint32            `json:"userLevel"`
}

func (v *DokodemoConfig) Build() (proto.Message, error) {
	if v.Address != nil {
		errors.PrintDeprecatedFeatureWarning(`"address"`, `"rewriteAddress"`)
		v.RewriteAddress = v.Address
	}
	if v.Port != 0 {
		errors.PrintDeprecatedFeatureWarning(`"port"`, `"rewritePort"`)
		v.RewritePort = v.Port
	}
	if v.Network != nil {
		errors.PrintDeprecatedFeatureWarning(`"network"`, `"allowedNetwork"`)
		v.AllowedNetwork = v.Network
	}
	config := new(dokodemo.Config)
	if v.RewriteAddress != nil {
		config.RewriteAddress = v.RewriteAddress.Build()
	}
	config.RewritePort = uint32(v.RewritePort)
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
