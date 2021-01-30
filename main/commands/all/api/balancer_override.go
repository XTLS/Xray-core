package api

import (
	"time"

	routerService "github.com/xtls/xray-core/app/router/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdBalancerOverride = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api bo [--server=127.0.0.1:8080] <-b balancer> selectors...",
	Short:       "balancer select override",
	Long: `
Override a balancer's selecting in a duration of time.

> Make sure you have "RoutingService" set in "config.api.services" 
of server config.

Once a balancer's selecting is overridden:

- The selectors of the balancer won't apply.
- The strategy of the balancer stops selecting qualified nodes 
  according to its settings, doing only the final pick.

Arguments:

	-r, -remove
		Remove the overridden

	-b, -balancer
		Tag of the balancer. Required

	-v, -validity
		Time minutes of the validity of overridden. Default 60

	-s, -server 
		The API server address. Default 127.0.0.1:8080

	-t, -timeout
		Timeout seconds to call API. Default 3

Example:

    {{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -b balancer selector1 selector2
    {{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -b balancer -r
`,
	Run: executeBalancerOverride,
}

func executeBalancerOverride(cmd *base.Command, args []string) {
	var (
		balancer string
		validity int64
		remove   bool
	)
	cmd.Flag.StringVar(&balancer, "b", "", "")
	cmd.Flag.StringVar(&balancer, "balancer", "", "")
	cmd.Flag.Int64Var(&validity, "v", 60, "")
	cmd.Flag.Int64Var(&validity, "validity", 60, "")
	cmd.Flag.BoolVar(&remove, "r", false, "")
	cmd.Flag.BoolVar(&remove, "remove", false, "")
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)

	if balancer == "" {
		base.Fatalf("balancer tag not specified")
	}

	conn, ctx, close := dialAPIServer()
	defer close()

	v := int64(0)
	if !remove {
		v = int64(time.Duration(validity) * time.Minute)
	}
	client := routerService.NewRoutingServiceClient(conn)
	r := &routerService.OverrideSelectingRequest{
		BalancerTag: balancer,
		Selectors:   cmd.Flag.Args(),
		Validity:    v,
	}
	_, err := client.OverrideSelecting(ctx, r)
	if err != nil {
		base.Fatalf("failed to perform balancer health checks: %s", err)
	}
}
