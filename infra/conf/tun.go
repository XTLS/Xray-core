package conf

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
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
	AutoSystemDnsToGateway bool     `json:"autoSystemDnsToGateway"`
	AutoSystemWfpBlockLeak []string `json:"autoSystemWfpBlockLeak"`
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
		AutoSystemDnsToGateway: v.AutoSystemDnsToGateway,
	}
	for _, leak := range v.AutoSystemWfpBlockLeak {
		switch leak := strings.ToLower(leak); leak {
		case "dns", "misconfigtun":
			config.AutoSystemWfpBlockLeak = append(config.AutoSystemWfpBlockLeak, leak)
		default:
			return nil, errors.New("unknown autoSystemWfpBlockLeak value: ", leak)
		}
	}
	// Each option needs other settings on the system it takes effect on: the
	// filters go along with the routes of autoSystemRoutingTable, "dns" lets
	// DNS through the TUN only, and autoSystemDnsToGateway points the system
	// DNS at the gateway.
	switch runtime.GOOS {
	case "windows":
		if len(config.AutoSystemWfpBlockLeak) > 0 && len(v.AutoSystemRoutingTable) == 0 {
			return nil, errors.New("autoSystemWfpBlockLeak needs autoSystemRoutingTable to be set")
		}
		if slices.Contains(config.AutoSystemWfpBlockLeak, "dns") && len(v.DNS) == 0 {
			return nil, errors.New(`autoSystemWfpBlockLeak "dns" needs dns to be set`)
		}
	case "linux":
		if v.AutoSystemDnsToGateway && len(v.Gateway) == 0 {
			return nil, errors.New("autoSystemDnsToGateway needs gateway to be set")
		}
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
