package api

import (
	routerService "github.com/xtls/xray-core/app/router/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdListRules = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api lsrules [--server=127.0.0.1:8080]",
	Short:       "List routing rules",
	Long: `
List routing rules in Xray.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080
`,
	Run: executeListRules,
}

func executeListRules(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)

	conn, ctx, close := dialAPIServer()
	defer close()

	client := routerService.NewRoutingServiceClient(conn)
	resp, err := client.ListRule(ctx, &routerService.ListRuleRequest{})
	if err != nil {
		base.Fatalf("failed to list rules: %s", err)
	}
	showJSONResponse(resp)
}
