package conf

import (
	"encoding/json"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/task"
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
	Users    []json.RawMessage   `json:"users"`
	Clients  []json.RawMessage   `json:"clients"`
	Defaults *VMessDefaultConfig `json:"default"`
}

// Build implements Buildable
func (c *VMessInboundConfig) Build() (proto.Message, error) {
	errors.PrintNonRemovalDeprecatedFeatureWarning("VMess (with no Forward Secrecy, etc.)", "VLESS Encryption")

	config := &inbound.Config{}

	if c.Defaults != nil {
		config.Default = c.Defaults.Build()
	}

	if c.Clients != nil {
		c.Users = c.Clients
	}
	config.User = make([]*protocol.User, len(c.Users))
	processUser := func(idx int) error {
		rawData := c.Users[idx]
		user := new(protocol.User)
		if err := json.Unmarshal(rawData, user); err != nil {
			return errors.New("invalid VMess user").Base(err)
		}
		account := new(VMessAccount)
		if err := json.Unmarshal(rawData, account); err != nil {
			return errors.New("invalid VMess user").Base(err)
		}

		u, err := uuid.ParseString(account.ID)
		if err != nil {
			return err
		}
		account.ID = u.String()

		user.Account = serial.ToTypedMessage(account.Build())
		config.User[idx] = user
		return nil
	}
	if err := task.ParallelForN(len(c.Users), processUser); err != nil {
		return nil, err
	}

	return config, nil
}

type VMessOutboundConfig struct {
	Address     *Address         `json:"address"`
	Port        uint16           `json:"port"`
	Level       uint32           `json:"level"`
	Email       string           `json:"email"`
	ID          string           `json:"id"`
	Security    string           `json:"security"`
	Experiments string           `json:"experiments"`
	Multiplex   *MultiplexConfig `json:"multiplex"`
}

// Build implements Buildable
func (c *VMessOutboundConfig) Build() (proto.Message, error) {
	errors.PrintNonRemovalDeprecatedFeatureWarning("VMess (with no Forward Secrecy, etc.)", "VLESS Encryption")

	multiplex, err := c.Multiplex.Build()
	if err != nil {
		return nil, err
	}
	config := &outbound.Config{Multiplex: multiplex}

	if c.Address == nil {
		return nil, errors.New(`VMess: "address" is not set`)
	}
	uid, err := uuid.ParseString(c.ID)
	if err != nil {
		return nil, err
	}

	account := &VMessAccount{
		ID:          uid.String(),
		Security:    c.Security,
		Experiments: c.Experiments,
	}
	spec := &protocol.ServerEndpoint{
		Address: c.Address.Build(),
		Port:    uint32(c.Port),
		User: &protocol.User{
			Level:   c.Level,
			Email:   c.Email,
			Account: serial.ToTypedMessage(account.Build()),
		},
	}

	config.Receiver = spec
	return config, nil
}
