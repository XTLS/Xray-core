package conf

import (
	"github.com/golang/protobuf/proto"
	"github.com/sagernet/sing/common"
	"github.com/xtls/xray-core/proxy/shadowtls"
)

type ShadowTLSServerConfig struct {
	Version                uint16                               `json:"version"`
	Password               string                               `json:"password,omitempty"`
	Users                  []ShadowTLSUser                      `json:"users,omitempty"`
	Handshake              *ShadowTLSHandshakeConfig            `json:"handshake"`
	HandshakeForServerName map[string]*ShadowTLSHandshakeConfig `json:"handshakeForServerName,omitempty"`
	StrictMode             bool                                 `json:"strictMode,omitempty"`
	Detour                 string                               `json:"detour"`
}

type ShadowTLSUser struct {
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
}

type ShadowTLSHandshakeConfig struct {
	Address *Address `json:"address"`
	Port    uint16   `json:"port"`
}

func (c *ShadowTLSServerConfig) Build() (proto.Message, error) {
	if c.Version == 0 {
		return nil, newError("shadow-tls version is not set.")
	}
	if c.Version == 3 && len(c.Users) == 0 {
		return nil, newError("shadow-tls users is not set.")
	}
	if c.Handshake == nil {
		return nil, newError("shadow-tls handshake config is not set.")
	}
	var handshakeForServerName map[string]*shadowtls.HandshakeConfig
	if c.HandshakeForServerName != nil {
		for serverName, serverConfig := range c.HandshakeForServerName {
			if serverConfig.Address == nil {
				return nil, newError("shadow-tls handshake server address is not set.")
			}
			if serverConfig.Port == 0 {
				return nil, newError("shadow-tls handshake server port is not set.")
			}
			handshakeForServerName[serverName] = &shadowtls.HandshakeConfig{
				Address: serverConfig.Address.Build(),
				Port:    uint32(serverConfig.Port),
			}
		}
	}
	if c.Handshake.Address == nil {
		return nil, newError("shadow-tls handshake server address is not set.")
	}
	if c.Handshake.Port == 0 {
		return nil, newError("shadow-tls handshake server port is not set.")
	}
	return &shadowtls.ServerConfig{
		Version:  uint32(c.Version),
		Password: c.Password,
		Users: common.Map(c.Users, func(it ShadowTLSUser) *shadowtls.User {
			return &shadowtls.User{
				Email:    it.Email,
				Password: it.Password,
			}
		}),
		Handshake: &shadowtls.HandshakeConfig{
			Address: c.Handshake.Address.Build(),
			Port:    uint32(c.Handshake.Port),
		},
		HandshakeForServerName: handshakeForServerName,
		StrictMode:             c.StrictMode,
		Detour:                 c.Detour,
	}, nil
}

type ShadowTLSClientConfig struct {
	Address  *Address `json:"address"`
	Port     uint16   `json:"port"`
	Version  uint16   `json:"version"`
	Password string   `json:"password,omitempty"`
}

func (c *ShadowTLSClientConfig) Build() (proto.Message, error) {
	if c.Version == 0 {
		return nil, newError("shadow-tls version is not set.")
	}
	if c.Address == nil {
		return nil, newError("shadow-tls server address is not set.")
	}
	if c.Port == 0 {
		return nil, newError("shadow-tls server port is not set.")
	}
	return &shadowtls.ClientConfig{
		Address:  c.Address.Build(),
		Port:     uint32(c.Port),
		Version:  uint32(c.Version),
		Password: c.Password,
	}, nil
}
