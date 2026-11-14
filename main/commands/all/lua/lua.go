package lua

import "github.com/xtls/xray-core/main/commands/base"

// CmdLua holds the Lua script commands.
var CmdLua = &base.Command{
	UsageLine: "{{.Exec}} lua",
	Short:     "Manage Lua scripts",
	Long:      "{{.Exec}} {{.LongName}} provides tools for local Lua scripts.",
	Commands: []*base.Command{
		cmdSign,
	},
}
