package selector

import (
    "context"
    "github.com/xtls/xray-core/common"
    "github.com/xtls/xray-core/core"
    "github.com/xtls/xray-core/proxy"
)

func init() {
    common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
        return New(ctx, config.(*Config))
    }))
}