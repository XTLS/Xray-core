package conf

import (
	"github.com/xtls/xray-core/proxy/tun"
	"google.golang.org/protobuf/proto"
)

type TunConfig struct {
	Name                   string   `json:"name"`
	MTU                    uint32   `json:"mtu"`
	MyGatewayIPs           []string `json:"myGatewayIPs"`
	DNS                    []string `json:"dns"`
	UserLevel              uint32   `json:"userLevel"`
	AutoRouteIPs           []string `json:"autoRouteIPs"`
	AutoOutboundsInterface *string  `json:"autoOutboundsInterface"`
}

func (v *TunConfig) Build() (proto.Message, error) {
	config := &tun.Config{
		Name:             v.Name,
		MTU:              v.MTU,
		Gateway:          v.MyGatewayIPs,
		DNS:              v.DNS,
		UserLevel:        v.UserLevel,
		AutoRoutingTable: v.AutoRouteIPs,
	}

	if v.AutoOutboundsInterface != nil {
		config.AutoOutboundsInterface = *v.AutoOutboundsInterface
	}

	if v.Name == "" {
		config.Name = "xray0"
	}

	if v.MTU == 0 {
		config.MTU = 1500
	}

	if len(config.AutoRoutingTable) > 0 && v.AutoOutboundsInterface == nil {
		config.AutoOutboundsInterface = "auto"
	}

	return config, nil
}
