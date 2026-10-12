package base64

import (
	"fmt"
	"os"
	"strings"

	xbase64 "github.com/xtls/xray-core/common/base64"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdDecode = &base.Command{
	UsageLine: "{{.Exec}} base64 decode [-gzip] [file | - | stdin:]",
	Short:     "Decode Base64",
	Long: fmt.Sprintf(`
Decode Base64 from a file; omit file or pass "-" or "stdin:" to read stdin.
Accepts %s, %s, or no prefix.
Use -gzip to decompress gzip; %s is decompressed automatically.

Examples:

	{{.Exec}} base64 decode encoded.txt
	{{.Exec}} base64 decode -gzip -
`, xbase64.Prefix, xbase64.GzipPrefix, xbase64.GzipPrefix),
}

var decodeGzipEnabled = cmdDecode.Flag.Bool("gzip", false, "Decompress the decoded bytes with gzip.")

func init() {
	cmdDecode.Run = executeDecode
}

func executeDecode(cmd *base.Command, args []string) {
	if len(args) > 1 {
		cmd.Usage()
	}
	input, err := readInput(args)
	if err != nil {
		base.Fatalf("failed to read input: %s", err)
	}
	value := strings.TrimSpace(string(input))
	if *decodeGzipEnabled && !strings.HasPrefix(value, xbase64.GzipPrefix) {
		value = xbase64.GzipPrefix + strings.TrimPrefix(value, xbase64.Prefix)
	}
	data, err := xbase64.Decode(value)
	if err != nil {
		base.Fatalf("failed to decode input: %s", err)
	}
	if _, err := os.Stdout.Write(data); err != nil {
		base.Fatalf("failed to write decoded output: %s", err)
	}
}
