package conf

import (
	"encoding/json"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/inbound"
	"github.com/xtls/xray-core/proxy/vmess/outbound"
	"google.golang.org/protobuf/proto"
)

type VMessAccount struct {
	ID          string `json:"id"`
	Security    string `json:"security"`
	Experiments string `json:"experiments"`
}

// Build implements Buildable
func (a *VMessAccount) Build() *vmess.Account {
	var st protocol.SecurityType
	switch strings.ToLower(a.Security) {
	case "aes-128-gcm":
		st = protocol.SecurityType_AES128_GCM
	case "chacha20-poly1305":
		st = protocol.SecurityType_CHACHA20_POLY1305
	case "auto":
		st = protocol.SecurityType_AUTO
	case "none":
		st = protocol.SecurityType_NONE
	case "zero":
		st = protocol.SecurityType_ZERO
	default:
		st = protocol.SecurityType_AUTO
	}
	return &vmess.Account{
		Id: a.ID,
		SecuritySettings: &protocol.SecurityConfig{
			Type: st,
		},
		TestsEnabled: a.Experiments,
	}
}

type VMessDetourConfig struct {
	ToTag string `json:"to"`
}

// Build implements Buildable
func (c *VMessDetourConfig) Build() *inbound.DetourConfig {
	return &inbound.DetourConfig{
		To: c.ToTag,
	}
}

type VMessDefaultConfig struct {
	Level byte `json:"level"`
}

// Build implements Buildable
func (c *VMessDefaultConfig) Build() *inbound.DefaultConfig {
	config := new(inbound.DefaultConfig)
	config.Level = uint32(c.Level)
	return config
}

type VMessInboundConfig struct {
	Users        []json.RawMessage   `json:"clients"`
	Defaults     *VMessDefaultConfig `json:"default"`
	DetourConfig *VMessDetourConfig  `json:"detour"`
}

// Build implements Buildable
func (c *VMessInboundConfig) Build() (proto.Message, error) {
	config := &inbound.Config{}

	if c.Defaults != nil {
		config.Default = c.Defaults.Build()
	}

	if c.DetourConfig != nil {
		config.Detour = c.DetourConfig.Build()
	}

	config.User = make([]*protocol.User, len(c.Users))
	for idx, rawData := range c.Users {
		user := new(protocol.User)
		if err := json.Unmarshal(rawData, user); err != nil {
			return nil, errors.New("invalid VMess user").Base(err)
		}
		account := new(VMessAccount)
		if err := json.Unmarshal(rawData, account); err != nil {
			return nil, errors.New("invalid VMess user").Base(err)
		}

		u, err := uuid.ParseString(account.ID)
		if err != nil {
			return nil, err
		}
		account.ID = u.String()

		user.Account = serial.ToTypedMessage(account.Build())
		config.User[idx] = user
	}

	return config, nil
}

type VMessOutboundTarget struct {
	Address *Address          `json:"address"`
	Port    uint16            `json:"port"`
	Users   []json.RawMessage `json:"users"`
}

type VMessOutboundConfig struct {
	Address     *Address               `json:"address"`
	Port        uint16                 `json:"port"`
	Level       uint32                 `json:"level"`
	Email       string                 `json:"email"`
	ID          string                 `json:"id"`
	Security    string                 `json:"security"`
	Experiments string                 `json:"experiments"`
	Receivers   []*VMessOutboundTarget `json:"vnext"`
}

// Build implements Buildable
func (c *VMessOutboundConfig) Build() (proto.Message, error) {
	config := new(outbound.Config)
	if c.Address != nil {
		c.Receivers = []*VMessOutboundTarget{
			{
				Address: c.Address,
				Port:    c.Port,
				Users:   []json.RawMessage{{}},
			},
		}
	}
	if len(c.Receivers) == 0 {
		return nil, errors.New("0 VMess receiver configured")
	}
	serverSpecs := make([]*protocol.ServerEndpoint, len(c.Receivers))
	for idx, rec := range c.Receivers {
		if len(rec.Users) == 0 {
			return nil, errors.New("0 user configured for VMess outbound")
		}
		if rec.Address == nil {
			return nil, errors.New("address is not set in VMess outbound config")
		}
		spec := &protocol.ServerEndpoint{
			Address: rec.Address.Build(),
			Port:    uint32(rec.Port),
		}
		for _, rawUser := range rec.Users {
			user := new(protocol.User)
			if c.Address != nil {
				user.Level = c.Level
				user.Email = c.Email
			} else {
				if err := json.Unmarshal(rawUser, user); err != nil {
					return nil, errors.New("invalid VMess user").Base(err)
				}
			}
			account := new(VMessAccount)
			if c.Address != nil {
				account.ID = c.ID
				account.Security = c.Security
				account.Experiments = c.Experiments
			} else {
				if err := json.Unmarshal(rawUser, account); err != nil {
					return nil, errors.New("invalid VMess user").Base(err)
				}
			}

			u, err := uuid.ParseString(account.ID)
			if err != nil {
				return nil, err
			}
			account.ID = u.String()

			user.Account = serial.ToTypedMessage(account.Build())
			spec.User = append(spec.User, user)
		}
		serverSpecs[idx] = spec
	}
	config.Receiver = serverSpecs
	return config, nil
}
