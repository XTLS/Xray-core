package conf

import (
	"encoding/json"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/http"
	"google.golang.org/protobuf/proto"
)

type HTTPAccount struct {
	Username string `json:"user,omitempty"`
	Password string `json:"pass,omitempty"`
}

func (v *HTTPAccount) Build() *http.Account {
	return &http.Account{
		Username: v.Username,
		Password: v.Password,
	}
}

type HTTPServerConfig struct {
	Timeout     uint32         `json:"timeout,omitempty"`
	Accounts    []*HTTPAccount `json:"accounts,omitempty"`
	Transparent bool           `json:"allowTransparent,omitempty"`
	UserLevel   uint32         `json:"userLevel,omitempty"`
}

func (c *HTTPServerConfig) Build() (proto.Message, error) {
	config := &http.ServerConfig{
		Timeout:          c.Timeout,
		AllowTransparent: c.Transparent,
		UserLevel:        c.UserLevel,
	}

	if len(c.Accounts) > 0 {
		config.Accounts = make(map[string]string)
		for _, account := range c.Accounts {
			config.Accounts[account.Username] = account.Password
		}
	}

	return config, nil
}

type HTTPRemoteConfig struct {
	Address *Address          `json:"address,omitempty"`
	Port    uint16            `json:"port,omitempty"`
	Users   []json.RawMessage `json:"users,omitempty"`
}

type HTTPClientConfig struct {
	Servers []*HTTPRemoteConfig `json:"servers,omitempty"`
	Headers map[string]string   `json:"headers,omitempty"`
}

func (v *HTTPClientConfig) Build() (proto.Message, error) {
	config := new(http.ClientConfig)
	config.Server = make([]*protocol.ServerEndpoint, len(v.Servers))
	for idx, serverConfig := range v.Servers {
		server := &protocol.ServerEndpoint{
			Address: serverConfig.Address.Build(),
			Port:    uint32(serverConfig.Port),
		}
		for _, rawUser := range serverConfig.Users {
			user := new(protocol.User)
			if err := json.Unmarshal(rawUser, user); err != nil {
				return nil, newError("failed to parse HTTP user").Base(err).AtError()
			}
			account := new(HTTPAccount)
			if err := json.Unmarshal(rawUser, account); err != nil {
				return nil, newError("failed to parse HTTP account").Base(err).AtError()
			}
			user.Account = serial.ToTypedMessage(account.Build())
			server.User = append(server.User, user)
		}
		config.Server[idx] = server
	}
	config.Header = make([]*http.Header, 0, 32)
	for key, value := range v.Headers {
		config.Header = append(config.Header, &http.Header{
			Key:   key,
			Value: value,
		})
	}
	return config, nil
}
