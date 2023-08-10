package conf

import (
	"github.com/xtls/xray-core/proxy/dokodemo"
	"google.golang.org/protobuf/proto"
)

type DokodemoConfig struct {
	Host         *Address     `json:"address"`
	PortValue    uint16       `json:"port"`
	NetworkList  *NetworkList `json:"network"`
	TimeoutValue uint32       `json:"timeout"`
	Redirect     bool         `json:"followRedirect"`
	UserLevel    uint32       `json:"userLevel"`
}

func (v *DokodemoConfig) Build() (proto.Message, error) {
	config := new(dokodemo.Config)
	if v.Host != nil {
		config.Address = v.Host.Build()
	}
	config.Port = uint32(v.PortValue)
	config.Networks = v.NetworkList.Build()
	config.Timeout = v.TimeoutValue
	config.FollowRedirect = v.Redirect
	config.UserLevel = v.UserLevel
	return config, nil
}
