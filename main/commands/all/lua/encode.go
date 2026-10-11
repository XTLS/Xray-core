package lua

import (
	"fmt"
	"io"
	"os"

	xlua "github.com/xtls/xray-core/common/lua"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdEncode = &base.Command{
	UsageLine: "{{.Exec}} lua encode [-gzip=false] [file | stdin:]",
	Short:     "Encode a Lua script for inline configuration",
	Long: `
Encode one file or stdin: as an inline Lua script for the script configuration field.
Files are read from the given path without searching configuration directories.
The original bytes are preserved; the script is not executed or validated.
The encoded string is written to stdout on one line, without quotes.

Arguments:

	-gzip=false
		Disable compression and output base64: instead of base64+gzip:.
		By default, gzip uses the highest compression level.

Examples:

	{{.Exec}} lua encode script.lua
	{{.Exec}} lua encode -gzip=false script.lua
	{{.Exec}} lua encode stdin:
`,
}

var gzipEnabled = cmdEncode.Flag.Bool("gzip", true, "Compress the script with gzip.")

func init() {
	cmdEncode.Run = executeEncode
}

func executeEncode(cmd *base.Command, args []string) {
	if len(args) != 1 {
		cmd.Usage()
	}
	var code []byte
	var err error
	if args[0] == "stdin:" {
		code, err = io.ReadAll(os.Stdin)
	} else {
		code, err = os.ReadFile(args[0])
	}
	if err != nil {
		base.Fatalf("failed to read script: %s", err)
	}
	script, err := xlua.Encode(code, *gzipEnabled)
	if err != nil {
		base.Fatalf("failed to encode script: %s", err)
	}
	if _, err := fmt.Fprintln(os.Stdout, script); err != nil {
		base.Fatalf("failed to write encoded script: %s", err)
	}
}
