package api

import (
	statsService "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdSysStats = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api statssys [--server=127.0.0.1:8080]",
	Short:       "Retrieve system statistics",
	Long: `
Retrieve system statistics from Xray.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080
`,
	Run: executeSysStats,
}

func executeSysStats(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)

	conn, ctx, close := dialAPIServer()
	defer close()

	client := statsService.NewStatsServiceClient(conn)
	r := &statsService.SysStatsRequest{}
	resp, err := client.GetSysStats(ctx, r)
	if err != nil {
		base.Fatalf("failed to get sys stats: %s", err)
	}
	showJSONResponse(resp)
}
