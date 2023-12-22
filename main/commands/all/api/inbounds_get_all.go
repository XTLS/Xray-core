package api

import (
	"fmt"

	handlerService "github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdGetAllInbounds = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api geti [--server=127.0.0.1:8080]",
	Short:       "Get all inbounds config",
	Long: `
Get all inbounds config from Xray.
Arguments:
	-s, -server
		The API server address. Default 127.0.0.1:8080
	-t, -timeout
		Timeout seconds to call API. Default 3
Example:
    {{.Exec}} {{.LongName}} --server=127.0.0.1:8080
`,
	Run: executeGetAllInbounds,
}

func executeGetAllInbounds(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)

	conn, ctx, close := dialAPIServer()
	defer close()

	client := handlerService.NewHandlerServiceClient(conn)
	req := &handlerService.GetAllInboundsRequest{}
	resp, err := client.GetAllInbounds(ctx, req)
	if err != nil {
		base.Fatalf("failed to get inbounds config: %s", err)
	}
	fmt.Print(resp.Configs)
}
