package base64

import "github.com/xtls/xray-core/main/commands/base"

// CmdBase64 holds all Base64 subcommands.
var CmdBase64 = &base.Command{
	UsageLine: "{{.Exec}} base64",
	Short:     "Encode and decode Base64",
	Long:      "{{.Exec}} {{.LongName}} provides tools to encode and decode arbitrary bytes.",
	Commands: []*base.Command{
		cmdEncode,
		cmdDecode,
	},
}
