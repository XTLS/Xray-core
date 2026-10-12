package base64

import (
	"fmt"
	"io"
	"os"

	xbase64 "github.com/xtls/xray-core/common/base64"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdEncode = &base.Command{
	UsageLine: "{{.Exec}} base64 encode [-gzip] <input-file | - | stdin:>",
	Short:     "Encode as Base64",
	Long: fmt.Sprintf(`
Encode input-file as Base64 with the %s prefix.
Pass "-" or "stdin:" to read stdin.
Use -gzip to compress and output %s.

Examples:

	{{.Exec}} base64 encode input.bin
	{{.Exec}} base64 encode -gzip input.bin
`, xbase64.Prefix, xbase64.GzipPrefix),
}

var gzipEnabled = cmdEncode.Flag.Bool("gzip", false, "Compress the input with gzip.")

func init() {
	cmdEncode.Run = executeEncode
}

func executeEncode(cmd *base.Command, args []string) {
	if len(args) != 1 {
		cmd.Usage()
	}

	var data []byte
	var err error
	if args[0] == "-" || args[0] == "stdin:" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(args[0])
	}
	if err != nil {
		base.Fatalf("failed to read input: %s", err)
	}

	value, err := xbase64.Encode(data, *gzipEnabled)
	if err != nil {
		base.Fatalf("failed to encode input: %s", err)
	}

	if _, err := fmt.Fprintln(os.Stdout, value); err != nil {
		base.Fatalf("failed to write encoded output: %s", err)
	}
}
