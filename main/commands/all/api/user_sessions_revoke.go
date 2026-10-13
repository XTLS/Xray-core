package api

import (
	"fmt"
	handlerService "github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdRevokeUserSessions = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api rmus [--server=127.0.0.1:8080] -tag=tag <email>...",
	Short:       "Revoke VLESS users and close their sessions",
	Run: func(cmd *base.Command, args []string) {
		setSharedFlags(cmd)
		var tag string
		cmd.Flag.StringVar(&tag, "tag", "", "")
		cmd.Flag.Parse(args)
		emails := cmd.Flag.Args()
		if tag == "" || len(emails) == 0 {
			base.Fatalf("inbound tag and user emails are required")
		}
		conn, ctx, close := dialAPIServer()
		defer close()
		client := handlerService.NewHandlerServiceClient(conn)
		for _, email := range emails {
			_, err := client.AlterInbound(ctx, &handlerService.AlterInboundRequest{Tag: tag, Operation: &serial.TypedMessage{Type: "xwork.vless.RevokeUserSessions.v1", Value: []byte(email)}})
			if err != nil {
				base.Fatalf("user session revocation failed: %s", err)
			}
		}
		fmt.Printf("Revoked %d user session set(s) in total.\n", len(emails))
	},
}
