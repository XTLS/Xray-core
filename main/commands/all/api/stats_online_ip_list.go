package api

import (
	statsService "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdOnlineStatsIpList = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api statsonlineiplist [--server=127.0.0.1:8080] [-email '']",
	Short:       "Retrieve a user's online IP addresses and access times",
	Long: `
Retrieve the online IP addresses and corresponding access timestamps for a user from Xray.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

	-email
		The user's email address.

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -email "xray@love.com"
`,
	Run: executeOnlineStatsIpList,
}

func executeOnlineStatsIpList(cmd *base.Command, args []string) {
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
	resp, err := client.GetStatsOnlineIpList(ctx, r)
	if err != nil {
		base.Fatalf("failed to get stats: %s", err)
	}
	showJSONResponse(resp)
}
