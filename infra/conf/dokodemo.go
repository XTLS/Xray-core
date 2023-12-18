package conf

import (
	"github.com/xtls/xray-core/proxy/dokodemo"
	"google.golang.org/protobuf/proto"
)

type DokodemoConfig struct {
	Host         *Address     `json:"address,omitempty"`
	PortValue    uint16       `json:"port,omitempty"`
	NetworkList  *NetworkList `json:"network,omitempty"`
	TimeoutValue uint32       `json:"timeout,omitempty"`
	Redirect     bool         `json:"followRedirect,omitempty"`
	UserLevel    uint32       `json:"userLevel,omitempty"`
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
