package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"google.golang.org/protobuf/proto"
)

type DokodemoConfig struct {
	Host         *Address     `json:"address"`
	PortValue    uint16       `json:"port"`
	NetworkList  *NetworkList `json:"network"`
	Redirect     bool         `json:"followRedirect"`
	UserLevel    uint32       `json:"userLevel"`

	// Deprecated. Remove before v26.x, for feature error trigger.
	TimeoutValue uint32       `json:"timeout"`
}

func (v *DokodemoConfig) Build() (proto.Message, error) {
	config := new(dokodemo.Config)
	if v.Host != nil {
		config.Address = v.Host.Build()
	}
	config.Port = uint32(v.PortValue)
	config.Networks = v.NetworkList.Build()
	if v.TimeoutValue > 0 {  // Remove before v26.x
		// After feature removal, change to PrintRemovedFeatureError, and keep it before v26.x
		errors.PrintDeprecatedFeatureWarning("timeout config in dokodemo-door", "userLevel")
		// Remove one line below before v25.x
		config.Timeout = v.TimeoutValue
	}
	config.FollowRedirect = v.Redirect
	config.UserLevel = v.UserLevel
	return config, nil
}
