package api

import (
	statsService "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdOnlineStatsIpList = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api statsonlineiplist [--server=127.0.0.1:8080] [-email '' | -all [-include-traffic] [-reset]]",
	Short:       "Retrieve a user's online IP addresses and access times",
	Long: `
Retrieve the online IP addresses and corresponding access timestamps for a user from Xray.
Use -all to retrieve all online users with their IPs and timestamps.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

	-email
		The user's email address.

	-all
		Retrieve all online users with their IPs and timestamps.

	-include-traffic
		Include traffic statistics when using -all.

	-reset
		Reset traffic counters after fetching. Only with -all and -include-traffic.

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -email "xray@love.com"
	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -all
	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -all -include-traffic
`,
	Run: executeOnlineStatsIpList,
}

func executeOnlineStatsIpList(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	email := cmd.Flag.String("email", "", "")
	all := cmd.Flag.Bool("all", false, "")
	includeTraffic := cmd.Flag.Bool("include-traffic", false, "")
	reset := cmd.Flag.Bool("reset", false, "")
	cmd.Flag.Parse(args)
	if *all && *email != "" {
		base.Fatalf("-all and -email are mutually exclusive")
	}
	if !*all && *email == "" {
		base.Fatalf("either -all or -email must be specified")
	}
	conn, ctx, close := dialAPIServer()
	defer close()

	client := statsService.NewStatsServiceClient(conn)

	if *all {
		r := &statsService.GetUsersStatsRequest{
			IncludeTraffic: *includeTraffic,
			Reset_:         *reset,
		}
		resp, err := client.GetUsersStats(ctx, r)
		if err != nil {
			base.Fatalf("failed to get stats: %s", err)
		}
		showJSONResponse(resp)
		return
	}

	statName := "user>>>" + *email + ">>>online"
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
