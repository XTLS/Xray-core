// +build !confonly

package tcp

import (
	"github.com/xtls/xray-core/v1/common"
	"github.com/xtls/xray-core/v1/transport/internet"
)

const protocolName = "tcp"

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
