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

func readInput(name string) ([]byte, error) {
	if name == "stdin:" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(name)
}
