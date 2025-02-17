package api

import (
	statsService "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdQueryStats = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api statsquery [--server=127.0.0.1:8080] [-pattern '']",
	Short:       "Query statistics",
	Long: `
Query statistics from Xray.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

	-pattern
		Filter pattern for the statistics query.

	-reset
		Reset the counter after fetching their values. Default false

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -pattern "counter_"
`,
	Run: executeQueryStats,
}

func executeQueryStats(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	pattern := cmd.Flag.String("pattern", "", "")
	reset := cmd.Flag.Bool("reset", false, "")
	cmd.Flag.Parse(args)

	conn, ctx, close := dialAPIServer()
	defer close()

	client := statsService.NewStatsServiceClient(conn)
	r := &statsService.QueryStatsRequest{
		Pattern: *pattern,
		Reset_:  *reset,
	}
	resp, err := client.QueryStats(ctx, r)
	if err != nil {
		base.Fatalf("failed to query stats: %s", err)
	}
	showJSONResponse(resp)
}
