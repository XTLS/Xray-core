package api

import (
	routerService "github.com/xtls/xray-core/app/router/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdBalancerOverride = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api bo [--server=127.0.0.1:8080] <-b balancer> outboundTag <-r>",
	Short:       "Override balancer",
	Long: `
Override the selection target of a balancer.

> Ensure that the "RoutingService" is properly configured under "config.api.services" in the server configuration.

Once the balancer's selection is overridden:

- The balancer's selection result will always be outboundTag

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

	-r, -remove
		Remove the existing override.

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
