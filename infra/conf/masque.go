package conf

import (
	"net/netip"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
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

type MasqueUserConfig struct {
	Pass  string `json:"pass"`
	Level uint32 `json:"level"`
	Email string `json:"email"`
}

type MasqueServerConfig struct {
	Users   []*MasqueUserConfig `json:"users"`
	Clients []*MasqueUserConfig `json:"clients"`
	Address []string            `json:"address"`
	MTU     uint32              `json:"mtu"`
}

func (c *MasqueServerConfig) Build() (proto.Message, error) {
	if c.Clients != nil {
		c.Users = c.Clients
	}
	config := &masque.ServerConfig{
		Address: c.Address,
		Mtu:     c.MTU,
	}
	emails := make(map[string]bool)
	for _, user := range c.Users {
		if user.Email == "" {
			return nil, errors.New(`MASQUE: "email" is empty`)
		}
		if strings.Contains(user.Email, ":") {
			return nil, errors.New(`MASQUE: invalid "email" `, user.Email)
		}
		if user.Pass == "" {
			return nil, errors.New(`MASQUE: "pass" of `, user.Email, ` is empty`)
		}
		email := strings.ToLower(user.Email)
		if emails[email] {
			return nil, errors.New(`MASQUE: duplicate "email" `, user.Email)
		}
		emails[email] = true
		config.Users = append(config.Users, &protocol.User{
			Email:   user.Email,
			Level:   user.Level,
			Account: serial.ToTypedMessage(&masque.Account{Password: user.Pass}),
		})
	}
	if len(c.Address) == 0 {
		return nil, errors.New(`MASQUE: "address" is not set`)
	}
	var v4, v6 bool
	for _, s := range c.Address {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, errors.New(`MASQUE: invalid "address" `, s).Base(err)
		}
		if prefix.Addr().Is4() && v4 || prefix.Addr().Is6() && v6 {
			return nil, errors.New(`MASQUE: "address" takes at most one IPv4 and one IPv6 prefix`)
		}
		v4 = v4 || prefix.Addr().Is4()
		v6 = v6 || prefix.Addr().Is6()
	}
	if c.MTU != 0 && (c.MTU < 1280 || c.MTU > 65535) {
		return nil, errors.New(`MASQUE: "mtu" must be between 1280 and 65535`)
	}
	return config, nil
}
