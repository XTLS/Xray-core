package api

import (
	"context"

	observatoryService "github.com/xtls/xray-core/app/observatory/command"
	routerService "github.com/xtls/xray-core/app/router/command"
	"github.com/xtls/xray-core/main/commands/base"
	"google.golang.org/grpc"
)

var cmdObservatoryQuery = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api obi [--server=127.0.0.1:8080] [outboundTag...]",
	Short:       "Query observatory results",
	Long: `
Query current observatory results. With no selector, all current results are returned.

Arguments:

	[outboundTag...]
		Return results for the specified outbound tags.

	-b, -balancer <balancerTag>
		Return results for all candidate outbounds of this balancer.
		RoutingService must also be enabled.

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds. Default 3

Examples:

	{{.Exec}} api obi --server=127.0.0.1:8080
	{{.Exec}} api obi proxy-a
	{{.Exec}} api obi -b proxy-balancer
`,
	Run: executeObservatoryQuery,
}

var cmdObservatoryProbe = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api obrq [--server=127.0.0.1:8080] [outboundTag...]",
	Short:       "Immediately probe outbounds",
	Long: `
Immediately probe selected outbounds and return the updated observatory results.
With no selector, all outbounds selected by the observatory configuration are probed.

Arguments:

	[outboundTag...]
		Probe the specified outbound tags.

	-b, -balancer <balancerTag>
		Probe all candidate outbounds of this balancer.
		RoutingService must also be enabled.

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds. Default 30

Examples:

	{{.Exec}} api obrq --server=127.0.0.1:8080
	{{.Exec}} api obrq proxy-a
	{{.Exec}} api obrq -b proxy-balancer
`,
	Run: executeObservatoryProbe,
}

func observatoryTargets(cmd *base.Command, args []string, timeout int) (string, []string) {
	var balancer string
	setSharedFlagsWithTimeout(cmd, timeout)
	cmd.Flag.StringVar(&balancer, "b", "", "")
	cmd.Flag.StringVar(&balancer, "balancer", "", "")
	if err := cmd.Flag.Parse(args); err != nil {
		base.Fatalf("failed to parse arguments: %s", err)
	}
	tags := cmd.Flag.Args()
	if balancer != "" && len(tags) != 0 {
		base.Fatalf("-b/-balancer and outboundTag arguments cannot be used together")
	}
	return balancer, tags
}

func resolveObservatoryTargets(ctx context.Context, conn grpc.ClientConnInterface, balancer string, tags []string) []string {
	if balancer == "" {
		return tags
	}
	client := routerService.NewRoutingServiceClient(conn)
	response, err := client.GetBalancerInfo(ctx, &routerService.GetBalancerInfoRequest{Tag: balancer})
	if err != nil {
		base.Fatalf("failed to resolve balancer %q: %s", balancer, err)
	}
	if response.Balancer == nil || response.Balancer.Candidates == nil || len(response.Balancer.Candidates.Tag) == 0 {
		base.Fatalf("balancer %q has no candidate outbounds", balancer)
	}
	return response.Balancer.Candidates.Tag
}

func executeObservatoryQuery(cmd *base.Command, args []string) {
	balancer, tags := observatoryTargets(cmd, args, 3)
	conn, ctx, close := dialAPIServer()
	defer close()
	tags = resolveObservatoryTargets(ctx, conn, balancer, tags)
	client := observatoryService.NewObservatoryServiceClient(conn)
	response, err := client.GetOutboundStatus(ctx, &observatoryService.GetOutboundStatusRequest{OutboundTags: tags})
	if err != nil {
		base.Fatalf("failed to query observatory: %s", err)
	}
	showJSONResponse(response)
}

func executeObservatoryProbe(cmd *base.Command, args []string) {
	balancer, tags := observatoryTargets(cmd, args, 30)
	conn, ctx, close := dialAPIServer()
	defer close()
	tags = resolveObservatoryTargets(ctx, conn, balancer, tags)
	client := observatoryService.NewObservatoryServiceClient(conn)
	response, err := client.ProbeOutboundStatus(ctx, &observatoryService.ProbeOutboundStatusRequest{OutboundTags: tags})
	if err != nil {
		base.Fatalf("failed to probe outbounds: %s", err)
	}
	showJSONResponse(response)
}
