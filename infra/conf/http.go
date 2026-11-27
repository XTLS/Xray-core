package conf

import (
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/http"
	"google.golang.org/protobuf/proto"
)

type HTTPAccount struct {
	Username string `json:"user"`
	Password string `json:"pass"`
}

func (v *HTTPAccount) Build() *http.Account {
	return &http.Account{
		Username: v.Username,
		Password: v.Password,
	}
}

type HTTPServerConfig struct {
	Users       []*HTTPAccount `json:"users"`
	Accounts    []*HTTPAccount `json:"accounts"`
	Transparent bool           `json:"allowTransparent"`
	UserLevel   uint32         `json:"userLevel"`
}

func (c *HTTPServerConfig) Build() (proto.Message, error) {
	config := &http.ServerConfig{
		AllowTransparent: c.Transparent,
		UserLevel:        c.UserLevel,
	}

	if c.Accounts != nil {
		c.Users = c.Accounts
	}
	// TODO: PB
	if len(c.Users) > 0 {
		config.Accounts = make(map[string]string)
		for _, account := range c.Users {
			config.Accounts[account.Username] = account.Password
		}
	}

	return config, nil
}

type HTTPClientConfig struct {
	Address  *Address          `json:"address"`
	Port     uint16            `json:"port"`
	Level    uint32            `json:"level"`
	Email    string            `json:"email"`
	Username string            `json:"user"`
	Password string            `json:"pass"`
	Headers  map[string]string `json:"headers"`
}

func (v *HTTPClientConfig) Build() (proto.Message, error) {
	config := new(http.ClientConfig)

	server := &protocol.ServerEndpoint{
		Address: v.Address.Build(),
		Port:    uint32(v.Port),
	}
	if len(v.Username) > 0 {
		account := &HTTPAccount{
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
	config.Header = make([]*http.Header, 0, 32)
	for key, value := range v.Headers {
		config.Header = append(config.Header, &http.Header{
			Key:   key,
			Value: value,
		})
	}
	return config, nil
}
