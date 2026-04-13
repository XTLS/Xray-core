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
	AutoSystemRoutingTable []string `json:"autoSystemRoutingTable"`
	AutoOutboundsInterface *string  `json:"autoOutboundsInterface"`
}

func (v *TunConfig) Build() (proto.Message, error) {
	config := &tun.Config{
		Name:                   v.Name,
		MTU:                    v.MTU,
		Gateway:                v.Gateway,
		DNS:                    v.DNS,
		UserLevel:              v.UserLevel,
		AutoSystemRoutingTable: v.AutoSystemRoutingTable,
	}
	if v.AutoOutboundsInterface != nil {
		config.AutoOutboundsInterface = *v.AutoOutboundsInterface
	}
	if len(v.AutoSystemRoutingTable) > 0 && v.AutoOutboundsInterface == nil {
		config.AutoOutboundsInterface = "auto"
	}

	if config.Name == "" {
		config.Name = "xray0"
	}
	if len(config.MTU) == 0 {
		config.MTU = []uint32{1500, 1280}
	}
	if len(config.MTU) == 1 {
		config.MTU = append(config.MTU, config.MTU[0])
	}
	return config, nil
}
