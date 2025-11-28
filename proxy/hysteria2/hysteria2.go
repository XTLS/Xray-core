package hysteria2

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
)

func init() {
	common.Must(common.RegisterConfig((*InboundConfig)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return cfg, nil
	}))

	common.Must(common.RegisterConfig((*OutboundConfig)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		c := cfg.(*OutboundConfig)
		tag := ""
		if full := session.FullHandlerFromContext(ctx); full != nil {
			tag = full.Tag()
		}

		var stream *internet.MemoryStreamConfig
		if ss, ok := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig); ok {
			stream = ss
		}

		return newOutboundHandler(tag, c, stream)
	}))
}
