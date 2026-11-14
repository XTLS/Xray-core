package base64

import (
	"fmt"
	"io"
	"os"
	"strings"

	xbase64 "github.com/xtls/xray-core/common/base64"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdDecode = &base.Command{
	UsageLine: "{{.Exec}} base64 decode [-gzip] <value | - | stdin:> [output-file]",
	Short:     "Decode Base64",
	Long: fmt.Sprintf(`
Decode a Base64 value, or pass "-" or "stdin:" to read stdin.
Write to output-file, or stdout if omitted.
Accepts %s, %s, or no prefix; gzip is enabled by %s or -gzip.

Examples:

	{{.Exec}} base64 decode eA== out.bin
	{{.Exec}} base64 decode -gzip H4sIAAAAAAAC/6sAAIMW3IwBAAAA out.bin
`, xbase64.Prefix, xbase64.GzipPrefix, xbase64.GzipPrefix),
}

var decodeGzipEnabled = cmdDecode.Flag.Bool("gzip", false, "Decompress the decoded bytes with gzip.")

func init() {
	cmdDecode.Run = executeDecode
}

func executeDecode(cmd *base.Command, args []string) {
	if len(args) == 0 || len(args) > 2 {
		cmd.Usage()
	}

	value := args[0]
	if value == "-" || value == "stdin:" {
		input, err := io.ReadAll(os.Stdin)
		if err != nil {
			base.Fatalf("failed to read input: %s", err)
		}
		value = string(input)
	}

	value = strings.TrimSpace(value)
	if *decodeGzipEnabled && !strings.HasPrefix(value, xbase64.GzipPrefix) {
		value = xbase64.GzipPrefix + strings.TrimPrefix(value, xbase64.Prefix)
	}

	data, err := xbase64.Decode(value)
	if err != nil {
		base.Fatalf("failed to decode input: %s", err)
	}

	if len(args) == 2 && args[1] != "-" {
		err = os.WriteFile(args[1], data, 0o666)
	} else {
		_, err = os.Stdout.Write(data)
	}
	if err != nil {
		base.Fatalf("failed to write decoded output: %s", err)
	}
}
