package api

import (
	"context"
	"fmt"

	"github.com/xtls/xray-core/common/protocol"

	handlerService "github.com/xtls/xray-core/app/proxyman/command"
	cserial "github.com/xtls/xray-core/common/serial"

	"github.com/xtls/xray-core/main/commands/base"
)

var cmdRemoveInboundUsers = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api rmu [--server=127.0.0.1:8080] <c1.json> [c2.json]...",
	Short:       "Remove users from inbounds",
	Long: `
Remove users from inbounds.
Arguments:
	-s, -server
		The API server address. Default 127.0.0.1:8080
	-t, -timeout
		Timeout seconds to call API. Default 3
Example:
    {{.Exec}} {{.LongName}} --server=127.0.0.1:8080  c1.json c2.json
`,
	Run: executeRemoveUsers,
}

func executeRemoveUsers(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)
	unnamedArgs := cmd.Flag.Args()
	inbs := extractInboundsConfig(unnamedArgs)

	conn, ctx, close := dialAPIServer()
	defer close()
	client := handlerService.NewHandlerServiceClient(conn)

	success := 0
	for _, inb := range inbs {
		success += executeInboundUserAction(ctx, client, inb, removeInboundUserAction)
	}
	fmt.Println("Removed", success, "user(s) in total.")
}

func removeInboundUserAction(ctx context.Context, client handlerService.HandlerServiceClient, tag string, user *protocol.User) error {
	fmt.Println("remove user:", user.Email)
	_, err := client.AlterInbound(ctx, &handlerService.AlterInboundRequest{
		Tag: tag,
		Operation: cserial.ToTypedMessage(
			&handlerService.RemoveUserOperation{
				Email: user.Email,
			}),
	})
	return err
}
