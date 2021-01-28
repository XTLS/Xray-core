package conf

import (
	"strings"

	"github.com/golang/protobuf/proto"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/shadowsocks"
)

func cipherFromString(c string) shadowsocks.CipherType {
	switch strings.ToLower(c) {
	case "aes-256-cfb":
		return shadowsocks.CipherType_AES_256_CFB
	case "aes-128-cfb":
		return shadowsocks.CipherType_AES_128_CFB
	case "chacha20":
		return shadowsocks.CipherType_CHACHA20
	case "chacha20-ietf":
		return shadowsocks.CipherType_CHACHA20_IETF
	case "aes-128-gcm", "aead_aes_128_gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm", "aead_aes_256_gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	case "none", "plain":
		return shadowsocks.CipherType_NONE
	default:
		return shadowsocks.CipherType_UNKNOWN
	}
}

type ShadowsocksUserConfig struct {
	Cipher   string `json:"method"`
	Password string `json:"password"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
}

type ShadowsocksServerConfig struct {
	Cipher      string                   `json:"method"`
	Password    string                   `json:"password"`
	Level       byte                     `json:"level"`
	Email       string                   `json:"email"`
	Users       []*ShadowsocksUserConfig `json:"clients"`
	NetworkList *NetworkList             `json:"network"`
}

func (v *ShadowsocksServerConfig) Build() (proto.Message, error) {
	config := new(shadowsocks.ServerConfig)
	config.Network = v.NetworkList.Build()

	if v.Users != nil {
		for _, user := range v.Users {
			account := &shadowsocks.Account{
				Password:   user.Password,
				CipherType: cipherFromString(user.Cipher),
			}
			if account.Password == "" {
				return nil, newError("Shadowsocks password is not specified.")
			}
			if account.CipherType < 5 || account.CipherType > 7 {
				return nil, newError("unsupported cipher method: ", user.Cipher)
			}
			config.Users = append(config.Users, &protocol.User{
				Email:   user.Email,
				Level:   uint32(user.Level),
				Account: serial.ToTypedMessage(account),
			})
		}
	} else {
		account := &shadowsocks.Account{
			Password:   v.Password,
			CipherType: cipherFromString(v.Cipher),
		}
		if account.Password == "" {
			return nil, newError("Shadowsocks password is not specified.")
		}
		if account.CipherType == shadowsocks.CipherType_UNKNOWN {
			return nil, newError("unknown cipher method: ", v.Cipher)
		}
		config.Users = append(config.Users, &protocol.User{
			Email:   v.Email,
			Level:   uint32(v.Level),
			Account: serial.ToTypedMessage(account),
		})
	}

	return config, nil
}

type ShadowsocksServerTarget struct {
	Address  *Address `json:"address"`
	Port     uint16   `json:"port"`
	Cipher   string   `json:"method"`
	Password string   `json:"password"`
	Email    string   `json:"email"`
	Level    byte     `json:"level"`
}

type ShadowsocksClientConfig struct {
	Servers []*ShadowsocksServerTarget `json:"servers"`
}

func (v *ShadowsocksClientConfig) Build() (proto.Message, error) {
	config := new(shadowsocks.ClientConfig)

	if len(v.Servers) == 0 {
		return nil, newError("0 Shadowsocks server configured.")
	}

	serverSpecs := make([]*protocol.ServerEndpoint, len(v.Servers))
	for idx, server := range v.Servers {
		if server.Address == nil {
			return nil, newError("Shadowsocks server address is not set.")
		}
		if server.Port == 0 {
			return nil, newError("Invalid Shadowsocks port.")
		}
		if server.Password == "" {
			return nil, newError("Shadowsocks password is not specified.")
		}
		account := &shadowsocks.Account{
			Password: server.Password,
		}
		account.CipherType = cipherFromString(server.Cipher)
		if account.CipherType == shadowsocks.CipherType_UNKNOWN {
			return nil, newError("unknown cipher method: ", server.Cipher)
		}

		ss := &protocol.ServerEndpoint{
			Address: server.Address.Build(),
			Port:    uint32(server.Port),
			User: []*protocol.User{
				{
					Level:   uint32(server.Level),
					Email:   server.Email,
					Account: serial.ToTypedMessage(account),
				},
			},
		}

		serverSpecs[idx] = ss
	}

	config.Server = serverSpecs

	return config, nil
}
