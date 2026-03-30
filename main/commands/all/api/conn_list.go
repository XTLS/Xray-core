package api

import (
	connService "github.com/xtls/xray-core/app/connectiontracker/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdConnList = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api connlist [--server=127.0.0.1:8080]",
	Short:       "List all active connections",
	Long: `
List all active proxy connections tracked by Xray.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

	-json
		Output as JSON.

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080
`,
	Run: executeConnList,
}

func executeConnList(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)

	conn, ctx, close := dialAPIServer()
	defer close()

	client := connService.NewConnTrackerServiceClient(conn)
	resp, err := client.ListConnections(ctx, &connService.ListConnectionsRequest{})
	if err != nil {
		base.Fatalf("failed to list connections: %s", err)
	}
	showJSONResponse(resp)
}
