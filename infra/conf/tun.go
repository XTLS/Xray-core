package conf

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strconv"

	"github.com/xtls/xray-core/proxy/tun"
	"google.golang.org/protobuf/proto"
)

type TunConfig struct {
	Name                   string   `json:"name"`
	Desc                   string   `json:"desc"`
	MTU                    uint32   `json:"mtu"`
	Gateway                []string `json:"gateway"`
	DNS                    []string `json:"dns"`
	UserLevel              uint32   `json:"userLevel"`
	AutoSystemRoutingTable []string `json:"autoSystemRoutingTable"`
	AutoOutboundsInterface *string  `json:"autoOutboundsInterface"`
}

func (v *TunConfig) Build() (proto.Message, error) {
	config := &tun.Config{
		Name:                   v.Name,
		Desc:                   v.Desc,
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
		name, err := GetAvailableTunName()
		if err != nil {
			return nil, err
		}
		config.Name = name
	}
	if config.Desc == "" {
		config.Desc = "Wintun"
	}
	if config.MTU == 0 {
		config.MTU = 1500
	}
	return config, nil
}

const (
	tunNamePrefix = "utun"
	minTunIndex   = 10
	maxTunIndex   = 1024
)

func GetAvailableTunName() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("fail to get system interface information: %w", err)
	}

	usedNames := make(map[string]struct{}, len(interfaces))
	for _, iface := range interfaces {
		usedNames[iface.Name] = struct{}{}
	}

	startIndex, err := randomInt(minTunIndex, maxTunIndex)
	if err != nil {
		return "", fmt.Errorf("fail to generate valid tun name: %w", err)
	}

	rangeSize := maxTunIndex - minTunIndex + 1

	for offset := 0; offset < rangeSize; offset++ {
		index := minTunIndex + (startIndex-minTunIndex+offset)%rangeSize
		name := tunNamePrefix + strconv.Itoa(index)

		if _, exists := usedNames[name]; !exists {
			return name, nil
		}
	}

	return "", fmt.Errorf(
		"no available TUN interface name in range %s%d-%s%d",
		tunNamePrefix,
		minTunIndex,
		tunNamePrefix,
		maxTunIndex,
	)
}

func randomInt(min, max int) (int, error) {
	value, err := rand.Int(
		rand.Reader,
		big.NewInt(int64(max-min+1)),
	)
	if err != nil {
		return 0, err
	}

	return min + int(value.Int64()), nil
}
