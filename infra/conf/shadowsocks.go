package conf

import (
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

func cipherFromString(c string) shadowsocks.CipherType {
	switch strings.ToLower(c) {
	case "aes-128-gcm", "aead_aes_128_gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm", "aead_aes_256_gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	case "xchacha20-poly1305", "aead_xchacha20_poly1305", "xchacha20-ietf-poly1305":
		return shadowsocks.CipherType_XCHACHA20_POLY1305
	case "none", "plain":
		return shadowsocks.CipherType_NONE
	default:
		return shadowsocks.CipherType_UNKNOWN
	}
}

type ShadowsocksUserConfig struct {
	Cipher   string   `json:"method"`
	Password string   `json:"password"`
	Level    byte     `json:"level"`
	Email    string   `json:"email"`
	Address  *Address `json:"address"`
	Port     uint16   `json:"port"`
}

type ShadowsocksServerConfig struct {
	Cipher      string                   `json:"method"`
	Password    string                   `json:"password"`
	Level       byte                     `json:"level"`
	Email       string                   `json:"email"`
	Users       []*ShadowsocksUserConfig `json:"clients"`
	NetworkList *NetworkList             `json:"network"`
	IVCheck     bool                     `json:"ivCheck"`
}

func (v *ShadowsocksServerConfig) Build() (proto.Message, error) {
	if C.Contains(shadowaead_2022.List, v.Cipher) {
		return buildShadowsocks2022(v)
	}

	config := new(shadowsocks.ServerConfig)
	config.Network = v.NetworkList.Build()

	if v.Users != nil {
		for _, user := range v.Users {
			account := &shadowsocks.Account{
				Password:   user.Password,
				CipherType: cipherFromString(user.Cipher),
				IvCheck:    v.IVCheck,
			}
			if account.Password == "" {
				return nil, newError("Shadowsocks password is not specified.")
			}
			if account.CipherType < shadowsocks.CipherType_AES_128_GCM ||
				account.CipherType > shadowsocks.CipherType_XCHACHA20_POLY1305 {
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
			IvCheck:    v.IVCheck,
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

func buildShadowsocks2022(v *ShadowsocksServerConfig) (proto.Message, error) {
	if len(v.Users) == 0 {
		config := new(shadowsocks_2022.ServerConfig)
		config.Method = v.Cipher
		config.Key = v.Password
		config.Network = v.NetworkList.Build()
		config.Email = v.Email
		return config, nil
	}
	
	if v.Cipher == "" {
		return nil, newError("shadowsocks 2022 (multi-user): missing server method")
	}
	if !strings.Contains(v.Cipher, "aes") {
		return nil, newError("shadowsocks 2022 (multi-user): only blake3-aes-*-gcm methods are supported")
	}

	if v.Users[0].Address == nil {
		config := new(shadowsocks_2022.MultiUserServerConfig)
		config.Method = v.Cipher
		config.Key = v.Password
		config.Network = v.NetworkList.Build()
	
		for _, user := range v.Users {
			if user.Cipher != "" {
				return nil, newError("shadowsocks 2022 (multi-user): users must have empty method")
			}
			config.Users = append(config.Users, &shadowsocks_2022.User{
				Key:   user.Password,
				Email: user.Email,
			})
		}
		return config, nil
	}

	config := new(shadowsocks_2022.RelayServerConfig)
	config.Method = v.Cipher
	config.Key = v.Password
	config.Network = v.NetworkList.Build()
	for _, user := range v.Users {
		if user.Cipher != "" {
			return nil, newError("shadowsocks 2022 (relay): users must have empty method")
		}
		if user.Address == nil {
			return nil, newError("shadowsocks 2022 (relay): all users must have relay address")
		}
		config.Destinations = append(config.Destinations, &shadowsocks_2022.RelayDestination{
			Key: user.Password,
			Email: user.Email,
			Address: user.Address.Build(),
			Port: uint32(user.Port),
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
	IVCheck  bool     `json:"ivCheck"`
	UoT      bool     `json:"uot"`
}

type ShadowsocksClientConfig struct {
	Servers []*ShadowsocksServerTarget `json:"servers"`
}

func (v *ShadowsocksClientConfig) Build() (proto.Message, error) {
	if len(v.Servers) == 0 {
		return nil, newError("0 Shadowsocks server configured.")
	}

	if len(v.Servers) == 1 {
		server := v.Servers[0]
		if C.Contains(shadowaead_2022.List, server.Cipher) {
			if server.Address == nil {
				return nil, newError("Shadowsocks server address is not set.")
			}
			if server.Port == 0 {
				return nil, newError("Invalid Shadowsocks port.")
			}
			if server.Password == "" {
				return nil, newError("Shadowsocks password is not specified.")
			}

			config := new(shadowsocks_2022.ClientConfig)
			config.Address = server.Address.Build()
			config.Port = uint32(server.Port)
			config.Method = server.Cipher
			config.Key = server.Password
			config.UdpOverTcp = server.UoT
			return config, nil
		}
	}

	config := new(shadowsocks.ClientConfig)
	serverSpecs := make([]*protocol.ServerEndpoint, len(v.Servers))
	for idx, server := range v.Servers {
		if C.Contains(shadowaead_2022.List, server.Cipher) {
			return nil, newError("Shadowsocks 2022 accept no multi servers")
		}
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

		account.IvCheck = server.IVCheck

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
