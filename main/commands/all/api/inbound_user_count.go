package api

import (
	handlerService "github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdInboundUserCount = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api inboundusercount [--server=127.0.0.1:8080] -tag=tag",
	Short:       "Retrieve inbound user count",
	Long: `
Retrieve the user count for a specified inbound tag.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

	-tag
		Inbound tag

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -tag="tag name"
`,
	Run: executeInboundUserCount,
}

func executeInboundUserCount(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	var tag string
	cmd.Flag.StringVar(&tag, "tag", "", "")
	cmd.Flag.Parse(args)

	conn, ctx, close := dialAPIServer()
	defer close()

	client := handlerService.NewHandlerServiceClient(conn)
	r := &handlerService.GetInboundUserRequest{
		Tag: tag,
	}
	resp, err := client.GetInboundUsersCount(ctx, r)
	if err != nil {
		base.Fatalf("failed to get inbound user count: %s", err)
	}
	showJSONResponse(resp)
}
