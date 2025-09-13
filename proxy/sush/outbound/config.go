package outbound

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

type Config struct {
	Address net.Address    `json:"address"`
	Port    net.Port       `json:"port"`
	User    *protocol.User `json:"user"`
	PSK     string         `json:"psk"`
}

type Account struct {
	ID           []byte            `json:"id"`
	Policy       string            `json:"policy"`
	CustomParams map[string]string `json:"customParams"`
}

func (c *Config) Validate() error {
	if c.Address == nil {
		return errors.New("address not configured")
	}
	if c.Port == 0 {
		return errors.New("port not configured")
	}
	if c.User == nil {
		return errors.New("user not configured")
	}
	if c.PSK == "" {
		return errors.New("PSK not configured")
	}
	return nil
}
