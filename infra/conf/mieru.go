package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/mieru"
	"github.com/xtls/xray-core/proxy/mieru/account"
	"google.golang.org/protobuf/proto"
)

// MieruClientConfig is the JSON configuration for a mieru outbound.
type MieruClientConfig struct {
	Address       *Address `json:"address"`
	Port          uint16   `json:"port"`
	Username      string   `json:"username"`
	Password      string   `json:"password"`
	Transport     string   `json:"transport"`
	Mtu           int32    `json:"mtu"`
	Multiplexing  string   `json:"multiplexing"`
	HandshakeMode int32    `json:"handshakeMode"`
}

func (c *MieruClientConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New("mieru outbound: missing address")
	}
	if c.Port == 0 {
		return nil, errors.New("mieru outbound: missing port")
	}
	if c.Username == "" {
		return nil, errors.New("mieru outbound: missing username")
	}
	if c.Password == "" {
		return nil, errors.New("mieru outbound: missing password")
	}

	acc := &account.Account{
		Username: c.Username,
		Password: c.Password,
	}
	server := &protocol.ServerEndpoint{
		Address: c.Address.Build(),
		Port:    uint32(c.Port),
		User: &protocol.User{
			Account: serial.ToTypedMessage(acc),
		},
	}
	return &mieru.ClientConfig{
		Server:        server,
		Transport:     c.Transport,
		Mtu:           c.Mtu,
		Multiplexing:  c.Multiplexing,
		HandshakeMode: c.HandshakeMode,
	}, nil
}

// MieruUserConfig describes a single mieru user.
type MieruUserConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Level    uint32 `json:"level"`
}

// MieruServerConfig is the JSON configuration for a mieru inbound.
type MieruServerConfig struct {
	Users               []*MieruUserConfig `json:"users"`
	Clients             []*MieruUserConfig `json:"clients"`
	Mtu                 int32              `json:"mtu"`
	UserHintIsMandatory bool               `json:"userHintIsMandatory"`
}

func (c *MieruServerConfig) Build() (proto.Message, error) {
	if c.Clients != nil {
		c.Users = c.Clients
	}
	if len(c.Users) == 0 {
		return nil, errors.New("mieru inbound: at least one user is required")
	}
	cfg := &mieru.ServerConfig{
		Mtu:                 c.Mtu,
		UserHintIsMandatory: c.UserHintIsMandatory,
	}
	cfg.Users = make([]*protocol.User, 0, len(c.Users))
	for _, u := range c.Users {
		if u.Username == "" {
			return nil, errors.New("mieru inbound user is missing username")
		}
		if u.Password == "" {
			return nil, errors.New("mieru inbound user is missing password")
		}
		acc := &account.Account{
			Username: u.Username,
			Password: u.Password,
		}
		cfg.Users = append(cfg.Users, &protocol.User{
			Email:   u.Email,
			Level:   u.Level,
			Account: serial.ToTypedMessage(acc),
		})
	}
	return cfg, nil
}
