package all

import "github.com/xtls/xray-core/v1/main/commands/base"

// go:generate go run github.com/xtls/xray-core/v1/common/errors/errorgen

func init() {
	base.RootCommand.Commands = append(
		base.RootCommand.Commands,
		cmdAPI,
		cmdConvert,
		cmdTLS,
		cmdUUID,
	)
}
