package conf

import (
	"github.com/golang/protobuf/proto"
	"github.com/xtls/xray-core/proxy/pf"
)

type PfConfig struct {
	Host        *Address     `json:"address"`
	PortValue   uint16       `json:"port"`
	NetworkList *NetworkList `json:"network"`
	Timeout     uint32       `json:"timeout"`
	Redirect    bool         `json:"followRedirect"`
	UserLevel   uint32       `json:"userLevel"`
}

func (v *PfConfig) Build() (proto.Message, error) {
	config := new(pf.Config)
	if v.Host != nil {
		config.Address = v.Host.Build()
	}
	config.Port = uint32(v.PortValue)
	config.Networks = v.NetworkList.Build()
	config.Timeout = v.Timeout
	config.FollowRedirect = v.Redirect
	config.UserLevel = v.UserLevel
	return config, nil
}
