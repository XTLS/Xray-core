package conf

import (
	"github.com/xtls/xray-core/proxy/tun"
	"google.golang.org/protobuf/proto"
)

type TunConfig struct {
	Name                   string   `json:"name"`
	MTU                    []uint32 `json:"mtu"`
	Gateway                []string `json:"gateway"`
	DNS                    []string `json:"dns"`
	UserLevel              uint32   `json:"userLevel"`
	AutoRoutingTable       []string `json:"autoRoutingTable"`
	AutoOutboundsInterface *string  `json:"autoOutboundsInterface"`
}

func (v *TunConfig) Build() (proto.Message, error) {
	config := &tun.Config{
		Name:             v.Name,
		MTU:              v.MTU,
		Gateway:          v.Gateway,
		DNS:              v.DNS,
		UserLevel:        v.UserLevel,
		AutoRoutingTable: v.AutoRoutingTable,
	}

	if v.AutoOutboundsInterface != nil {
		config.AutoOutboundsInterface = *v.AutoOutboundsInterface
	}

	if v.Name == "" {
		config.Name = "xray0"
	}

	if len(v.MTU) == 1 {
		v.MTU = append(v.MTU, v.MTU[0])
	}
	if len(v.MTU) == 0 {
		v.MTU = []uint32{1500, 1280}
	}

	if len(config.AutoRoutingTable) > 0 && v.AutoOutboundsInterface == nil {
		config.AutoOutboundsInterface = "auto"
	}

	return config, nil
}
