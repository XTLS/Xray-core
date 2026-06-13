package api

import (
	connService "github.com/xtls/xray-core/app/connectiontracker/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdConnUserStats = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api connuserstats [--server=127.0.0.1:8080] -email <email>",
	Short:       "Get traffic stats and connection count for a user",
	Long: `
Retrieve the aggregated uplink bytes, downlink bytes, and active connection
count for a given user across all inbounds.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

	-email <email>
		The user's email address (required).

	-json
		Output as JSON.

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -email "user@example.com"
`,
	Run: executeConnUserStats,
}

func executeConnUserStats(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	email := cmd.Flag.String("email", "", "")
	cmd.Flag.Parse(args)

	if *email == "" {
		base.Fatalf("email is required")
	}

	conn, ctx, close := dialAPIServer()
	defer close()

	client := connService.NewConnTrackerServiceClient(conn)
	resp, err := client.GetUserStats(ctx, &connService.GetUserStatsRequest{
		Email: *email,
	})
	if err != nil {
		base.Fatalf("failed to get user stats: %s", err)
	}
	showJSONResponse(resp)
}
