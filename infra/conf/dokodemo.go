package conf

import (
	"github.com/xtls/xray-core/proxy/dokodemo"
	"google.golang.org/protobuf/proto"
)

type DokodemoConfig struct {
	Address        *Address     `json:"address"`
	Port           uint16       `json:"port"`
	Network        *NetworkList `json:"network"`
	FollowRedirect bool         `json:"followRedirect"`
	UserLevel      uint32       `json:"userLevel"`
}

func (v *DokodemoConfig) Build() (proto.Message, error) {
	config := new(dokodemo.Config)
	if v.Address != nil {
		config.Address = v.Address.Build()
	}
	config.Port = uint32(v.Port)
	config.Networks = v.Network.Build()
	config.FollowRedirect = v.FollowRedirect
	config.UserLevel = v.UserLevel
	return config, nil
}
