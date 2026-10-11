package lua

import "github.com/xtls/xray-core/main/commands/base"

// CmdLua holds all Lua subcommands.
var CmdLua = &base.Command{
	UsageLine: "{{.Exec}} lua",
	Short:     "Lua tools",
	Long:      "{{.Exec}} {{.LongName}} provides tools for Lua scripts.",
	Commands: []*base.Command{
		cmdEncode,
	},
}
