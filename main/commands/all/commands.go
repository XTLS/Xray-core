package all

import (
	"github.com/xmplusdev/xray-core/main/commands/all/api"
	"github.com/xmplusdev/xray-core/main/commands/all/convert"
	"github.com/xmplusdev/xray-core/main/commands/all/tls"
	"github.com/xmplusdev/xray-core/main/commands/base"
)

// go:generate go run github.com/xmplusdev/xray-core/common/errors/errorgen

func init() {
	base.RootCommand.Commands = append(
		base.RootCommand.Commands,
		api.CmdAPI,
		convert.CmdConvert,
		tls.CmdTLS,
		cmdUUID,
		cmdX25519,
		cmdWG,
	)
}
