package api

import (
	statsService "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdAllUsersOnlineInfo = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api statsonlineinfo [--server=127.0.0.1:8080]",
	Short:       "Retrieve all online users with their IPs and timestamps",
	Long: `
Retrieve all online users with their IP addresses and last-seen timestamps.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080
`,
	Run: executeAllUsersOnlineInfo,
}

func executeAllUsersOnlineInfo(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)
	conn, ctx, close := dialAPIServer()
	defer close()

	client := statsService.NewStatsServiceClient(conn)
	r := &statsService.GetAllOnlineUsersRequest{}
	resp, err := client.GetAllUsersOnlineInfo(ctx, r)
	if err != nil {
		base.Fatalf("failed to get stats: %s", err)
	}
	showJSONResponse(resp)
}
