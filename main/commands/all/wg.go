package all

import (
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdWG = &base.Command{
	CustomFlags: true,
	UsageLine:   `{{.Exec}} wg [-i "private key (base64.StdEncoding)"]`,
	Short:       `Generate key pair for X25519 key exchange (WireGuard)`,
	Long: `
Generate key pair for X25519 key exchange (WireGuard).

Arguments:

	-i
		Generate key pair from private key (base64.StdEncoding).

Example:

	Random: {{.Exec}} {{.LongName}}
	From private key: {{.Exec}} {{.LongName}} -i "private key (base64.StdEncoding)"
`,
	Run: executeWG,
}

func executeWG(cmd *base.Command, args []string) {
	var input_wireguard = cmd.Flag.String("i", "", "")
	cmd.Flag.Parse(args)
	Curve25519Genkey(true, *input_wireguard)
}
