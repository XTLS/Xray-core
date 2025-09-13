package outbound

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/sush"
)

func init() {
	common.Must(common.RegisterConfig((*sush.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewXrayHandler(ctx, config)
	}))
}

// NewHandler creates a new Sush outbound handler compatible with Xray-core
func NewXrayHandler(ctx context.Context, config interface{}) (outbound.Handler, error) {
	sushnfig, ok := config.(*susushboundConfig)
	if !ok {
		return nil, errors.New("invalid config type for Sush outbound")
	}

	handler, err := NewHandler(ctx, convertConfig(sushnfig))
	if err != nil {
		return nil, errors.New("failed to create Sush outbound handler").Base(err)
	}

	return handler, nil
}

// convertConfig converts protobuf config to internal config
func convertConfig(pbConfig *sushutboundConfig) *Config {
	if len(pbConfig.Vnext) == 0 {
		return &Config{
			Address: net.LocalHostIP,
			Port:    net.Port(443),
			PSK:     "default-psk",
		}
	}

	// Use first server endpoint
	endpoint := pbConfig.Vnext[0]

	// Parse address
	address := net.ParseAddress(endpoint.Address)

	// Create user from first available user or default
	var user *protocol.User
	if len(endpoint.Users) > 0 {
		SushUser := endpoint.Users[0]
		account := &Account{
			ID:     []byte(SushUser.Id),
			Policy: SushUser.Policy,
		}
		user = &protocol.User{
			Level:   SushUser.Level,
			Email:   SushUser.Id + "@Sush.local",
			Account: protocol.AsAccount(account),
		}
	} else {
		// Default user
		account := &Account{
			ID:     []byte("default"),
			Policy: "default",
		}
		user = &protocol.User{
			Level:   0,
			Email:   "default@Sush.local",
			Account: protocol.AsAccount(account),
		}
	}

	psk := "default-psk"
	if len(endpoint.Users) > 0 && endpoint.Users[0].Psk != "" {
		psk = endpoint.Users[0].Psk
	}

	return &Config{
		Address: address,
		Port:    net.Port(endpoint.Port),
		User:    user,
		PSK:     psk,
	}
}
