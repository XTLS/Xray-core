package conf

import (
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/dns"
	"google.golang.org/protobuf/proto"
)

type DNSOutboundConfig struct {
	Network    Network  `json:"network"`
	Address    *Address `json:"address"`
	Port       uint16   `json:"port"`
	UserLevel  uint32   `json:"userLevel"`
	NonIPQuery string   `json:"nonIPQuery"`
	BlockType  string   `json:"blockType"`
}

func (c *DNSOutboundConfig) Build() (proto.Message, error) {
	config := &dns.Config{
		Server: &net.Endpoint{
			Network: c.Network.Build(),
			Port:    uint32(c.Port),
		},
		UserLevel: c.UserLevel,
	}
	if c.Address != nil {
		config.Server.Address = c.Address.Build()
	}
	switch c.NonIPQuery {
	case "":
		c.NonIPQuery = "drop"
	case "drop", "skip":
	default:
		return nil, errors.New(`unknown "nonIPQuery": `, c.NonIPQuery)
	}
	config.Non_IPQuery = c.NonIPQuery
	parts := strings.Split(c.BlockType, ",")
	var BlockType []int32
	if c.BlockType != "" {
		for _, part := range parts {
			num, err := strconv.Atoi(part)
			if err != nil {
				return nil, errors.New("Block type must be int, received:", part)
			}
			BlockType = append(BlockType, int32(num))
		}
	}
	config.BlockType = BlockType
	return config, nil
}
