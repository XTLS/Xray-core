package api

import (
	routerService "github.com/xtls/xray-core/app/router/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdBalancerOverride = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api bo [--server=127.0.0.1:8080] <-b balancer> outboundTag",
	Short:       "balancer override",
	Long: `
Override a balancer's selection.

> Make sure you have "RoutingService" set in "config.api.services" 
of server config.

Once a balancer's selecting is overridden:

- The balancer's selection result will always be outboundTag

Arguments:

	-r, -remove
		Remove the overridden

	-r, -remove
		Remove the override

	-s, -server 
		The API server address. Default 127.0.0.1:8080

	-t, -timeout
		Timeout seconds to call API. Default 3

Example:

    {{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -b balancer tag
    {{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -b balancer -r
`,
	Run: executeBalancerOverride,
}

func executeBalancerOverride(cmd *base.Command, args []string) {
	var (
		balancer string
		remove   bool
	)
	cmd.Flag.StringVar(&balancer, "b", "", "")
	cmd.Flag.StringVar(&balancer, "balancer", "", "")
	cmd.Flag.BoolVar(&remove, "r", false, "")
	cmd.Flag.BoolVar(&remove, "remove", false, "")
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)

	if balancer == "" {
		base.Fatalf("balancer tag not specified")
	}

	conn, ctx, close := dialAPIServer()
	defer close()

	client := routerService.NewRoutingServiceClient(conn)
	target := ""
	if !remove {
		target = cmd.Flag.Args()[0]
	}
	r := &routerService.OverrideBalancerTargetRequest{
		BalancerTag: balancer,
		Target:      target,
	}

	_, err := client.OverrideBalancerTarget(ctx, r)
	if err != nil {
		base.Fatalf("failed to perform balancer health checks: %s", err)
	}
}
