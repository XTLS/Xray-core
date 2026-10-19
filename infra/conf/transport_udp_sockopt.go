package conf

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

// UDPSocketConfig describes a UDP listener, not the stream carrying proxy requests.
// It deliberately has no TCP, dialer or stream settings to inherit.
type UDPSocketConfig struct {
	Mark          int32                  `json:"mark"`
	TProxy        string                 `json:"tproxy"`
	V6only        bool                   `json:"v6only"`
	CustomSockopt []*CustomSockoptConfig `json:"customSockopt"`
}

func (c *UDPSocketConfig) UnmarshalJSON(data []byte) error {
	type config UDPSocketConfig
	var value config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return errors.New("invalid udpSockopt").Base(err)
	}
	*c = UDPSocketConfig(value)
	return nil
}

func (c *UDPSocketConfig) Build() (*internet.SocketConfig, error) {
	switch strings.ToLower(c.TProxy) {
	case "", "off", "tproxy", "redirect":
	default:
		return nil, errors.New("unsupported UDP tproxy mode: ", c.TProxy)
	}
	for i, option := range c.CustomSockopt {
		if option == nil {
			return nil, errors.New("customSockopt[", i, "] must be an object")
		}
		switch option.Network {
		case "", "udp", "udp4", "udp6":
		default:
			return nil, errors.New("customSockopt[", i, "] network must be udp, udp4 or udp6, or omitted")
		}
		// The general socket config defaults level to TCP. Require an explicit
		// level here instead of silently attempting a TCP option on a UDP socket.
		for _, number := range []string{option.Level, option.Opt} {
			if _, err := strconv.Atoi(number); err != nil {
				return nil, errors.New("customSockopt[", i, "] requires integer level and opt").Base(err)
			}
		}
		switch option.Type {
		case "int":
			if _, err := strconv.Atoi(option.Value); err != nil {
				return nil, errors.New("customSockopt[", i, "] requires an integer value").Base(err)
			}
		case "str":
		default:
			return nil, errors.New("customSockopt[", i, "] type must be int or str")
		}
	}
	return (&SocketConfig{
		Mark: c.Mark, TProxy: c.TProxy, V6only: c.V6only, CustomSockopt: c.CustomSockopt,
	}).Build()
}
