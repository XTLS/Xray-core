package api

import (
	routerService "github.com/xtls/xray-core/app/router/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdBalancerCheck = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api bc [--server=127.0.0.1:8080] [balancer]...",
	Short:       "balancer health check",
	Long: `
Perform instant health checks for specific balancers. If no 
balancer tag specified, check all balancers.

> Make sure you have "RoutingService" set in "config.api.services" 
of server config.

Arguments:

	-s, -server 
		The API server address. Default 127.0.0.1:8080

	-t, -timeout
		Timeout seconds to call API. Default 3

Example:

    {{.Exec}} {{.LongName}} --server=127.0.0.1:8080 balancer1 balancer2
`,
	Run: executeBalancerCheck,
}

func executeBalancerCheck(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)

	conn, ctx, close := dialAPIServer()
	defer close()

	client := routerService.NewRoutingServiceClient(conn)
	r := &routerService.CheckBalancersRequest{BalancerTags: cmd.Flag.Args()}
	_, err := client.CheckBalancers(ctx, r)
	if err != nil {
		base.Fatalf("failed to perform balancer health checks: %s", err)
	}
}
