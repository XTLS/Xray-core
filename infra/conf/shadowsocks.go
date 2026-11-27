package conf

import (
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"google.golang.org/protobuf/proto"
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
	Users       []*ShadowsocksUserConfig `json:"users"`
	Clients     []*ShadowsocksUserConfig `json:"clients"`
	NetworkList *NetworkList             `json:"network"`
}

func (v *ShadowsocksServerConfig) Build() (proto.Message, error) {
	errors.PrintNonRemovalDeprecatedFeatureWarning("Shadowsocks (with no Forward Secrecy, etc.)", "VLESS Encryption")

	if v.Clients != nil {
		v.Users = v.Clients
	}

	if _, err := shadowsocks_2022.GetCipherMethod(v.Cipher); err == nil {
		return buildShadowsocks2022(v)
	}

	config := new(shadowsocks.ServerConfig)
	config.Network = v.NetworkList.Build()

	if v.Users != nil {
		if len(v.Users) > 0 {
			config.Users = make([]*protocol.User, len(v.Users))
			processUser := func(idx int) error {
				user := v.Users[idx]
				account := &shadowsocks.Account{
					Password:   user.Password,
					CipherType: cipherFromString(user.Cipher),
				}
				if account.Password == "" {
					return errors.New("Shadowsocks password is not specified.")
				}
				if account.CipherType < shadowsocks.CipherType_AES_128_GCM ||
					account.CipherType > shadowsocks.CipherType_XCHACHA20_POLY1305 {
					return errors.New("unsupported cipher method: ", user.Cipher)
				}
				config.Users[idx] = &protocol.User{
					Email:   user.Email,
					Level:   uint32(user.Level),
					Account: serial.ToTypedMessage(account),
				}
				return nil
			}
			if err := task.ParallelForN(len(v.Users), processUser); err != nil {
				return nil, err
			}
		}
	} else {
		account := &shadowsocks.Account{
			Password:   v.Password,
			CipherType: cipherFromString(v.Cipher),
		}
		if account.Password == "" {
			return nil, errors.New("Shadowsocks password is not specified.")
		}
		if account.CipherType == shadowsocks.CipherType_UNKNOWN {
			return nil, errors.New("unknown cipher method: ", v.Cipher)
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
	v.Cipher = strings.ToLower(v.Cipher)
	if len(v.Users) == 0 {
		config := new(shadowsocks_2022.ServerConfig)
		config.Method = v.Cipher
		config.Key = v.Password
		config.Network = v.NetworkList.Build()
		config.Email = v.Email
		config.Level = int32(v.Level)
		return config, nil
	}

	if v.Cipher == "" {
		return nil, errors.New("shadowsocks 2022 (multi-user): missing server method")
	}
	if !strings.Contains(v.Cipher, "aes") {
		return nil, errors.New("shadowsocks 2022 (multi-user): only blake3-aes-*-gcm methods are supported")
	}

	if v.Users[0].Address == nil {
		config := new(shadowsocks_2022.MultiUserServerConfig)
		config.Method = v.Cipher
		config.Key = v.Password
		config.Network = v.NetworkList.Build()

		config.Users = make([]*protocol.User, len(v.Users))
		processUser := func(idx int) error {
			user := v.Users[idx]
			if user.Cipher != "" {
				return errors.New("shadowsocks 2022 (multi-user): users must have empty method")
			}
			account := &shadowsocks_2022.Account{
				Key: user.Password,
			}
			config.Users[idx] = &protocol.User{
				Email:   user.Email,
				Level:   uint32(user.Level),
				Account: serial.ToTypedMessage(account),
			}
			return nil
		}
		if err := task.ParallelForN(len(v.Users), processUser); err != nil {
			return nil, err
		}
		return config, nil
	}

	config := new(shadowsocks_2022.RelayServerConfig)
	config.Method = v.Cipher
	config.Key = v.Password
	config.Network = v.NetworkList.Build()
	for _, user := range v.Users {
		if user.Cipher != "" {
			return nil, errors.New("shadowsocks 2022 (relay): users must have empty method")
		}
		if user.Address == nil {
			return nil, errors.New("shadowsocks 2022 (relay): all users must have relay address")
		}
		config.Destinations = append(config.Destinations, &shadowsocks_2022.RelayDestination{
			Key:     user.Password,
			Email:   user.Email,
			Address: user.Address.Build(),
			Port:    uint32(user.Port),
			Level:   int32(user.Level),
		})
	}
	return config, nil
}

type ShadowsocksClientConfig struct {
	Address  *Address `json:"address"`
	Port     uint16   `json:"port"`
	Level    byte     `json:"level"`
	Email    string   `json:"email"`
	Cipher   string   `json:"method"`
	Password string   `json:"password"`
}

func (v *ShadowsocksClientConfig) Build() (proto.Message, error) {
	errors.PrintNonRemovalDeprecatedFeatureWarning("Shadowsocks (with no Forward Secrecy, etc.)", "VLESS Encryption")

	if v.Address == nil {
		return nil, errors.New("Shadowsocks server address is not set.")
	}
	if v.Port == 0 {
		return nil, errors.New("Invalid Shadowsocks port.")
	}
	if v.Password == "" {
		return nil, errors.New("Shadowsocks password is not specified.")
	}

	if _, err := shadowsocks_2022.GetCipherMethod(v.Cipher); err == nil {
		config := &shadowsocks_2022.ClientConfig{
			Address: v.Address.Build(),
			Port:    uint32(v.Port),
			Method:  v.Cipher,
			Key:     v.Password,
		}
		return config, nil
	}

	config := new(shadowsocks.ClientConfig)
	if cipherFromString(v.Cipher) == shadowsocks.CipherType_UNKNOWN {
		return nil, errors.New("unknown cipher method: ", v.Cipher)
	}
	ss := &protocol.ServerEndpoint{
		Address: v.Address.Build(),
		Port:    uint32(v.Port),
		User: &protocol.User{
			Level: uint32(v.Level),
			Email: v.Email,
			Account: serial.ToTypedMessage(&shadowsocks.Account{
				Password:   v.Password,
				CipherType: cipherFromString(v.Cipher),
			}),
		},
	}
	config.Server = ss

	return config, nil
}
