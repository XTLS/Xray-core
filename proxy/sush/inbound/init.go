package inbound

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/proxy/sush"
)

func init() {
	common.Must(common.RegisterConfig((*sush.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewHandler(ctx, config)
	}))
}

// NewHandler creates a new Sush inbound handler compatible with Xray-core
func NewHandler(ctx context.Context, config interface{}) (inbound.Handler, error) {
	sushnfig, ok := config.(*susushoundConfig)
	if !ok {
		return nil, errors.New("invalid config type for Sush inbound")
	}

	handler, err := NewSushHandler(ctx, convertConfig(sushnfig))
	if err != nil {
		return nil, errors.New("failed to create Sush inbound handler").Base(err)
	}

	return handler, nil
}

// convertConfig converts protobuf config to internal config
func convertConfig(pbConfig *sushnboundConfig) *Config {
	config := &Config{
		Users: make([]*UserConfig, len(pbConfig.Users)),
		PSK:   "default-psk", // Use first user's PSK if available
	}

	// Convert users and extract PSK from first user
	for i, user := range pbConfig.Users {
		config.Users[i] = &UserConfig{
			ID:     user.Id,
			Email:  user.Id + "@Sush.local", // Generate email from ID
			Policy: user.Policy,
		}

		// Use first user's PSK as the global PSK
		if i == 0 && user.Psk != "" {
			config.PSK = user.Psk
		}
	}

	// Convert fallback config (use first fallback if available)
	if len(pbConfig.Fallbacks) > 0 {
		fallback := pbConfig.Fallbacks[0]
		config.Fallback = &FallbackConfig{
			Dest: fallback.Dest,
			Type: "tcp", // Default type since Type field doesn't exist in protobuf
			Path: fallback.Path,
		}
	}

	return config
}
