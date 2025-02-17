package api

import (
	logService "github.com/xtls/xray-core/app/log/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdRestartLogger = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api restartlogger [--server=127.0.0.1:8080]",
	Short:       "Restart the logger",
	Long: `
Restart the logger of Xray.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080
`,
	Run: executeRestartLogger,
}

func executeRestartLogger(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)

	conn, ctx, close := dialAPIServer()
	defer close()

	client := logService.NewLoggerServiceClient(conn)
	r := &logService.RestartLoggerRequest{}
	resp, err := client.RestartLogger(ctx, r)
	if err != nil {
		base.Fatalf("failed to restart logger: %s", err)
	}
	showJSONResponse(resp)
}
