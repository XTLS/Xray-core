package all

import (
	"github.com/jobberrt/xray-core/main/commands/all/api"
	"github.com/jobberrt/xray-core/main/commands/all/tls"
	"github.com/jobberrt/xray-core/main/commands/base"
)

// go:generate go run github.com/xtls/xray-core/common/errors/errorgen

func init() {
	base.RootCommand.Commands = append(
		base.RootCommand.Commands,
		api.CmdAPI,
		// cmdConvert,
		tls.CmdTLS,
		cmdUUID,
	)
}
