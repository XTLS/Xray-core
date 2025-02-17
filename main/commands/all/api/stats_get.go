package api

import (
	statsService "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdGetStats = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api stats [--server=127.0.0.1:8080] [-name '']",
	Short:       "Retrieve statistics",
	Long: `
Retrieve the statistics from Xray.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

	-name
		Name of the counter.

	-reset
		Reset the counter after fetching their values. Default false

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -name "inbound>>>statin>>>traffic>>>downlink"
`,
	Run: executeGetStats,
}

func executeGetStats(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	statName := cmd.Flag.String("name", "", "")
	reset := cmd.Flag.Bool("reset", false, "")
	cmd.Flag.Parse(args)

	conn, ctx, close := dialAPIServer()
	defer close()

	client := statsService.NewStatsServiceClient(conn)
	r := &statsService.GetStatsRequest{
		Name:   *statName,
		Reset_: *reset,
	}
	resp, err := client.GetStats(ctx, r)
	if err != nil {
		base.Fatalf("failed to get stats: %s", err)
	}
	showJSONResponse(resp)
}
