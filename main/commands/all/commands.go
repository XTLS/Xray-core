package all

import (
	"github.com/4nd3r5on/Xray-core/main/commands/all/api"
	"github.com/4nd3r5on/Xray-core/main/commands/all/tls"
	"github.com/4nd3r5on/Xray-core/main/commands/base"
)

// go:generate go run github.com/4nd3r5on/Xray-core/common/errors/errorgen

func init() {
	base.RootCommand.Commands = append(
		base.RootCommand.Commands,
		api.CmdAPI,
		// cmdConvert,
		tls.CmdTLS,
		cmdUUID,
		cmdX25519,
		cmdWG,
	)
}
