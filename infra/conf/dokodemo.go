package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"google.golang.org/protobuf/proto"
)

type DokodemoConfig struct {
	AllowedNetwork *NetworkList      `json:"allowedNetwork"`
	RewriteAddress *Address          `json:"rewriteAddress"`
	RewritePort    uint16            `json:"rewritePort"`
	Network        *NetworkList      `json:"network"`
	Address        *Address          `json:"address"`
	Port           uint16            `json:"port"`
	PortMap        map[string]string `json:"portMap"`
	FollowRedirect bool              `json:"followRedirect"`
	UserLevel      uint32            `json:"userLevel"`
}

func (v *DokodemoConfig) Build() (proto.Message, error) {
	if v.Network != nil {
		v.AllowedNetwork = v.Network
	}
	if v.Address != nil {
		v.RewriteAddress = v.Address
	}
	if v.Port != 0 {
		v.RewritePort = v.Port
	}
	config := new(dokodemo.Config)
	config.AllowedNetworks = v.AllowedNetwork.Build()
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
	config.FollowRedirect = v.FollowRedirect
	config.UserLevel = v.UserLevel
	return config, nil
}
