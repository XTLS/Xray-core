package wireguard

import (
	"context"

	"github.com/xtls/xray-core/common"
)

func init() {
	common.Must(common.RegisterConfig((*DeviceConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		deviceConfig := config.(*DeviceConfig)
		if deviceConfig.IsClient {
			return NewClient(ctx, deviceConfig)
		} else {
			return NewServer(ctx, deviceConfig)
		}
	}))
}
