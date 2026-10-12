package base64

import (
	"fmt"
	"os"

	xbase64 "github.com/xtls/xray-core/common/base64"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdEncode = &base.Command{
	UsageLine: "{{.Exec}} base64 encode [-gzip] [file | - | stdin:]",
	Short:     "Encode as Base64",
	Long: fmt.Sprintf(`
Encode a file as Base64 with the %s prefix.
Omit file or pass "-" or "stdin:" to read stdin. Use -gzip to compress and output %s.

Examples:

	{{.Exec}} base64 encode data.bin
	{{.Exec}} base64 encode -gzip data.bin
	{{.Exec}} base64 encode
`, xbase64.Prefix, xbase64.GzipPrefix),
}

var gzipEnabled = cmdEncode.Flag.Bool("gzip", false, "Compress the input with gzip.")

func init() {
	cmdEncode.Run = executeEncode
}

func executeEncode(cmd *base.Command, args []string) {
	if len(args) > 1 {
		cmd.Usage()
	}
	data, err := readInput(args)
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
