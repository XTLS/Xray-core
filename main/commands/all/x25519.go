package all

import (
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdX25519 = &base.Command{
	UsageLine: `{{.Exec}} x25519 [-i "private key (base64.RawURLEncoding)"] [--std-encoding]`,
	Short:     `Generate key pair for X25519 key exchange (REALITY, VLESS Encryption)`,
	Long: `
Generate key pair for X25519 key exchange (REALITY, VLESS Encryption).

Random: {{.Exec}} x25519

From private key: {{.Exec}} x25519 -i "private key (base64.RawURLEncoding)"
For Std Encoding: {{.Exec}} x25519 --std-encoding
`,
}

func init() {
	cmdX25519.Run = executeX25519 // break init loop
}

var input_stdEncoding = cmdX25519.Flag.Bool("std-encoding", false, "")
var input_x25519 = cmdX25519.Flag.String("i", "", "")

func executeX25519(cmd *base.Command, args []string) {
	Curve25519Genkey(false, *input_x25519)
}
