package api

import (
	statsService "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdGetAllOnlineUsers = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api statsgetallonlineusers [--server=127.0.0.1:8080]",
	Short:       "Retrieve array of all online users",
	Long: `
Retrieve array of all online users.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080"
`,
	Run: executeGetAllOnlineUsers,
}

func executeGetAllOnlineUsers(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)
	conn, ctx, close := dialAPIServer()
	defer close()

	client := statsService.NewStatsServiceClient(conn)
	r := &statsService.GetAllOnlineUsersRequest{}
	resp, err := client.GetAllOnlineUsers(ctx, r)
	if err != nil {
		base.Fatalf("failed to get stats: %s", err)
	}
	showJSONResponse(resp)
}
