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

func (c ShadowTLSUser) Build() *shadowtls.User {
	return &shadowtls.User{
		Email:    c.Email,
		Password: c.Password,
	}
}

type ShadowTLSHandshakeConfig struct {
	Address *Address `json:"address"`
	Port    uint16   `json:"port"`
}

func (c ShadowTLSHandshakeConfig) Build() *shadowtls.HandshakeConfig {
	return &shadowtls.HandshakeConfig{
		Address: c.Address.Build(),
		Port:    uint32(c.Port),
	}
}

func (c *ShadowTLSServerConfig) Build() (proto.Message, error) {
	var handshakeForServerName map[string]*shadowtls.HandshakeConfig
	if c.HandshakeForServerName != nil {
		for serverName, serverConfig := range c.HandshakeForServerName {
			handshakeForServerName[serverName] = serverConfig.Build()
		}
	}
	return &shadowtls.ServerConfig{
		Version:                uint32(c.Version),
		Password:               c.Password,
		Users:                  common.Map(c.Users, ShadowTLSUser.Build),
		Handshake:              c.Handshake.Build(),
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
	return &shadowtls.ClientConfig{
		Address:  c.Address.Build(),
		Port:     uint32(c.Port),
		Version:  uint32(c.Version),
		Password: c.Password,
	}, nil
}
