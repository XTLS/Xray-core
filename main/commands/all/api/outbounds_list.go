package api

import (
	handlerService "github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdListOutbounds = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api lso [--server=127.0.0.1:8080]",
	Short:       "List outbounds",
	Long: `
List outbounds in Xray.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080
`,
	Run: executeListOutbounds,
}

func executeListOutbounds(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)

	conn, ctx, close := dialAPIServer()
	defer close()

	client := handlerService.NewHandlerServiceClient(conn)
	resp, err := client.ListOutbounds(ctx, &handlerService.ListOutboundsRequest{})
	if err != nil {
		base.Fatalf("failed to list outbounds: %s", err)
	}
	showJSONResponse(resp)
}
