package conf

import (
	"github.com/xtls/xray-core/proxy/tun"
	"google.golang.org/protobuf/proto"
)

type TunConfig struct {
	Name                   string   `json:"name"`
	MTU                    uint32   `json:"mtu"`
	Gateway                []string `json:"gateway"`
	DNS                    []string `json:"dns"`
	UserLevel              uint32   `json:"userLevel"`
	AutoSystemRoutingTable []string `json:"autoSystemRoutingTable"`
	AutoOutboundsInterface *string  `json:"autoOutboundsInterface"`
	Stack                  string   `json:"stack"`
	Address                []string `json:"address"`
	DNSMode                string   `json:"dnsMode"`
	DNSAddress             []string `json:"dnsAddress"`
	StrictRoute            bool     `json:"strictRoute"`
}

func (v *TunConfig) Build() (proto.Message, error) {
	config := &tun.Config{
		Name:                   v.Name,
		MTU:                    v.MTU,
		Gateway:                v.Gateway,
		DNS:                    v.DNS,
		UserLevel:              v.UserLevel,
		AutoSystemRoutingTable: v.AutoSystemRoutingTable,
		Stack:                  v.Stack,
		Address:                v.Address,
		DnsMode:                v.DNSMode,
		DnsAddress:             v.DNSAddress,
		StrictRoute:            v.StrictRoute,
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
	if config.MTU == 0 {
		config.MTU = 1500
	}
	if config.Stack == "" {
		config.Stack = "gvisor"
	}
	if config.DnsMode == "" {
		config.DnsMode = "hijack"
	}
	return config, nil
}
