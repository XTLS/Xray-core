package all

import (
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdX25519 = &base.Command{
	CustomFlags: true,
	UsageLine:   `{{.Exec}} x25519 [-i "private key (base64.RawURLEncoding)"] [--std-encoding]`,
	Short:       `Generate key pair for X25519 key exchange (REALITY, VLESS Encryption)`,
	Long: `
Generate key pair for X25519 key exchange (REALITY, VLESS Encryption).

Arguments:

	-i
		Generate key pair from private key (base64.RawURLEncoding).
	
	--std-encoding
		Use standard Base64 encoding format instead of URL-friendly format.

Example:

	Random: {{.Exec}} {{.LongName}}
	From private key: {{.Exec}} {{.LongName}} -i "private key (base64.RawURLEncoding)"
	For Std Encoding: {{.Exec}} {{.LongName}} --std-encoding
`,
	Run: executeX25519,
}

func executeX25519(cmd *base.Command, args []string) {
	var input_stdEncoding = cmd.Flag.Bool("std-encoding", false, "")
	var input_x25519 = cmd.Flag.String("i", "", "")
	cmd.Flag.Parse(args)
	Curve25519Genkey(*input_stdEncoding, *input_x25519)
}
