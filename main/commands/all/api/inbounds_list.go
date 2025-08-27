package api

import (
	handlerService "github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdListInbounds = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api lsi [--server=127.0.0.1:8080] [--isOnlyTags=true]",
	Short:       "List inbounds",
	Long: `
List inbounds in Xray.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080
`,
	Run: executeListInbounds,
}

func executeListInbounds(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	var isOnlyTagsStr string
	cmd.Flag.StringVar(&isOnlyTagsStr, "isOnlyTags", "", "")
	cmd.Flag.Parse(args)
	isOnlyTags := isOnlyTagsStr == "true"

	conn, ctx, close := dialAPIServer()
	defer close()

	client := handlerService.NewHandlerServiceClient(conn)

	resp, err := client.ListInbounds(ctx, &handlerService.ListInboundsRequest{IsOnlyTags: isOnlyTags})
	if err != nil {
		base.Fatalf("failed to list inbounds: %s", err)
	}
	showJSONResponse(resp)
}
