package api

import (
	"fmt"

	handlerService "github.com/xtls/xray-core/app/proxyman/command"
	cserial "github.com/xtls/xray-core/common/serial"

	"github.com/xtls/xray-core/main/commands/base"
)

var cmdRemoveInboundUsers = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api rmu [--server=127.0.0.1:8080] -tag=tag <email1> [email2]...",
	Short:       "Remove users from inbounds",
	Long: `
Remove users from inbounds.
Arguments:
	-s, -server
		The API server address. Default 127.0.0.1:8080
	-t, -timeout
		Timeout seconds to call API. Default 3
	-tag
		Inbound tag
Example:
    {{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -tag="vless-in" "xray@love.com" ...
`,
	Run: executeRemoveUsers,
}

func executeRemoveUsers(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	var tag string
	cmd.Flag.StringVar(&tag, "tag", "", "")
	cmd.Flag.Parse(args)
	emails := cmd.Flag.Args()
	if len(tag) < 1 {
		base.Fatalf("inbound tag not specified")
	}

	conn, ctx, close := dialAPIServer()
	defer close()
	client := handlerService.NewHandlerServiceClient(conn)

	success := 0
	for _, email := range emails {
		fmt.Println("remove user:", email)
		_, err := client.AlterInbound(ctx, &handlerService.AlterInboundRequest{
			Tag: tag,
			Operation: cserial.ToTypedMessage(
				&handlerService.RemoveUserOperation{
					Email: email,
				}),
		})
		if err == nil {
			success += 1
		} else {
			fmt.Println(err)
		}
	}
	fmt.Println("Removed", success, "user(s) in total.")
}
