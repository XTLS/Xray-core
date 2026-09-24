package conf

import (
	"net/netip"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/masque"
	"google.golang.org/protobuf/proto"
)

type MasqueClientConfig struct {
	Address   *Address `json:"address"`
	Port      uint16   `json:"port"`
	RemoteDNS []string `json:"remoteDNS"`
}

func (c *MasqueClientConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New(`MASQUE: "address" is not set`)
	}
	if c.Port == 0 {
		return nil, errors.New(`MASQUE: "port" is not set`)
	}
	for _, s := range c.RemoteDNS {
		if _, err := netip.ParseAddr(s); err != nil {
			return nil, errors.New(`MASQUE: invalid "remoteDNS" `, s).Base(err)
		}
	}
	return &masque.ClientConfig{
		Server: &protocol.ServerEndpoint{
			Address: c.Address.Build(),
			Port:    uint32(c.Port),
		},
		RemoteDns: c.RemoteDNS,
	}, nil
}
