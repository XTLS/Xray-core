package base64

import (
	"io"
	"os"

	"github.com/xtls/xray-core/main/commands/base"
)

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

func readInput(args []string) ([]byte, error) {
	if len(args) == 0 || args[0] == "-" || args[0] == "stdin:" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(args[0])
}
