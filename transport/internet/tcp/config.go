package tcp

import (
	"github.com/4nd3r5on/Xray-core/common"
	"github.com/4nd3r5on/Xray-core/transport/internet"
)

const protocolName = "tcp"

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
