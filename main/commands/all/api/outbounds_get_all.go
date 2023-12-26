package api

import (
	"fmt"

	handlerService "github.com/xtls/xray-core/app/proxyman/command"
	creflect "github.com/xtls/xray-core/common/reflect"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdGetAllOutbounds = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api geto [--server=127.0.0.1:8080]",
	Short:       "Get all outbounds config",
	Long: `
Get all outbounds config from Xray.
Arguments:
	-s, -server
		The API server address. Default 127.0.0.1:8080
	-t, -timeout
		Timeout seconds to call API. Default 3
Example:
    {{.Exec}} {{.LongName}} --server=127.0.0.1:8080
`,
	Run: executeGetAllOutbounds,
}

func executeGetAllOutbounds(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)

	conn, ctx, close := dialAPIServer()
	defer close()

	client := handlerService.NewHandlerServiceClient(conn)
	req := &handlerService.GetAllOutboundsRequest{}
	resp, err := client.GetAllOutbounds(ctx, req)
	if err != nil {
		base.Fatalf("failed to get outbound config: %s", err)
	}
	if j, ok := creflect.MarshalToJson(resp.Configs); !ok {
		base.Fatalf("failed to marshal configs to json")
	} else {
		fmt.Print(j)
	}
}
