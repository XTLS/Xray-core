package all

import (
	"github.com/hosemorinho412/xray-core/main/commands/base"
)

var cmdWG = &base.Command{
	UsageLine: `{{.Exec}} wg [-i "private key (base64.StdEncoding)"]`,
	Short:     `Generate key pair for wireguard key exchange`,
	Long: `
Generate key pair for wireguard key exchange.

Random: {{.Exec}} wg

From private key: {{.Exec}} wg -i "private key (base64.StdEncoding)"
`,
}

func init() {
	cmdWG.Run = executeWG // break init loop
}

var input_wireguard = cmdWG.Flag.String("i", "", "")

func executeWG(cmd *base.Command, args []string) {
	Curve25519Genkey(true, *input_wireguard)
}
