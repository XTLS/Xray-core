package api

import (
	statsService "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdOnlineStats = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api statsonline [--server=127.0.0.1:8080] [-name '']",
	Short:       "Get online user",
	Long: `
Get statistics from Xray.
Arguments:
	-s, -server 
		The API server address. Default 127.0.0.1:8080
	-t, -timeout
		Timeout seconds to call API. Default 3
	-email
		email of the user.
	-reset
		Reset the counter to fetching its value.
Example:
	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -email "user1@test.com"
`,
	Run: executeOnlineStats,
}

func executeOnlineStats(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	email := cmd.Flag.String("email", "", "")
	cmd.Flag.Parse(args)
	statName := "user>>>" + *email + ">>>online"
	conn, ctx, close := dialAPIServer()
	defer close()

	client := statsService.NewStatsServiceClient(conn)
	r := &statsService.GetStatsRequest{
		Name:   statName,
		Reset_: false,
	}
	resp, err := client.GetStatsOnline(ctx, r)
	if err != nil {
		base.Fatalf("failed to get stats: %s", err)
	}
	showJSONResponse(resp)
}
