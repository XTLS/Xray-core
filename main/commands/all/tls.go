package all

import (
	"github.com/xtls/xray-core/v1/main/commands/all/tlscmd"
	"github.com/xtls/xray-core/v1/main/commands/base"
)

var cmdTLS = &base.Command{
	UsageLine: "{{.Exec}} tls",
	Short:     "TLS tools",
	Long: `{{.Exec}} tls provides tools for TLS.
	`,

	Commands: []*base.Command{
		tlscmd.CmdCert,
		tlscmd.CmdPing,
	},
}
