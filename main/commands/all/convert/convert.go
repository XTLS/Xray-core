package convert

import (
	"github.com/xtls/xray-core/main/commands/base"
)

// CmdConvert do config convertion
var CmdConvert = &base.Command{
	UsageLine: "{{.Exec}} convert",
	Short:     "Convert configs",
	Long: `{{.Exec}} {{.LongName}} provides tools to convert config.
`,
	Commands: []*base.Command{
		cmdProtobuf,
		cmdJson,
	},
}
