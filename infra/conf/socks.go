package conf

import (
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/socks"
	"google.golang.org/protobuf/proto"
)

type SocksAccount struct {
	Username string `json:"user"`
	Password string `json:"pass"`
}

func (v *SocksAccount) Build() *socks.Account {
	return &socks.Account{
		Username: v.Username,
		Password: v.Password,
	}
}

const (
	AuthMethodNoAuth   = "noauth"
	AuthMethodUserPass = "password"
)

type SocksServerConfig struct {
	AuthMethod string          `json:"auth"`
	Users      []*SocksAccount `json:"users"`
	Accounts   []*SocksAccount `json:"accounts"`
	UDP        bool            `json:"udp"`
	Host       *Address        `json:"ip"`
	UserLevel  uint32          `json:"userLevel"`
}

func (v *SocksServerConfig) Build() (proto.Message, error) {
	config := new(socks.ServerConfig)
	switch v.AuthMethod {
	case AuthMethodNoAuth:
		config.AuthType = socks.AuthType_NO_AUTH
	case AuthMethodUserPass:
		config.AuthType = socks.AuthType_PASSWORD
	default:
		config.AuthType = socks.AuthType_NO_AUTH
	}

	if v.Accounts != nil {
		v.Users = v.Accounts
	}
	// TODO: PB
	if len(v.Users) > 0 {
		config.Accounts = make(map[string]string, len(v.Users))
		for _, account := range v.Users {
			config.Accounts[account.Username] = account.Password
		}
	}

	config.UdpEnabled = v.UDP
	if v.Host != nil {
		config.Address = v.Host.Build()
	}

	config.UserLevel = v.UserLevel
	return config, nil
}

type SocksClientConfig struct {
	Address  *Address `json:"address"`
	Port     uint16   `json:"port"`
	Level    uint32   `json:"level"`
	Email    string   `json:"email"`
	Username string   `json:"user"`
	Password string   `json:"pass"`
}

func (v *SocksClientConfig) Build() (proto.Message, error) {
	config := new(socks.ClientConfig)

	server := &protocol.ServerEndpoint{
		Address: v.Address.Build(),
		Port:    uint32(v.Port),
	}
	if len(v.Username) > 0 {
		account := &SocksAccount{
			Username: v.Username,
			Password: v.Password,
		}
		user := &protocol.User{
			Level:   v.Level,
			Email:   v.Email,
			Account: serial.ToTypedMessage(account.Build()),
		}
		server.User = user
	}

	config.Server = server
	return config, nil
}
