package api

import (
	"fmt"
	"strings"

	observatoryService "github.com/xtls/xray-core/app/observatory/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdObservatoryReset = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api obsreset [--server=127.0.0.1:8080] [-prefix <prefix>]... [tag]...",
	Short:       "Reset burstObservatory health results of outbounds",
	Long: `
Reset the health results (RTT samples and failures) that burstObservatory
keeps for outbounds, either for single tags or for whole tag prefixes.

The reset outbounds are checked again right away in background, with the
usual limits (pingConfig.startCheck checks at once per tag prefix, 4 by
default), so they get back to the leastLoad balancer without waiting for
the next scheduled round. Saved results are updated too, so a restart does
not bring the old samples back.

> Ensure that "ObservatoryService" is enabled under "config.api.services"
> in the server configuration, and that burstObservatory is configured.

Arguments:

	[tag]...
		Exact outbound tags to reset, e.g. cf_22

	-p, -prefix <prefix>
		Reset every outbound whose tag starts with <prefix>, e.g. cf_
		Can be repeated.

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

	-json
		Use json output.

Example:

    {{.Exec}} {{.LongName}} cf_22
    {{.Exec}} {{.LongName}} cf_22 f_7
    {{.Exec}} {{.LongName}} -prefix cf_
    {{.Exec}} {{.LongName}} -prefix cf_ -prefix gc_ aws_3
`,
	Run: executeObservatoryReset,
}

type prefixFlags []string

func (p *prefixFlags) String() string     { return strings.Join(*p, ",") }
func (p *prefixFlags) Set(v string) error { *p = append(*p, v); return nil }

func executeObservatoryReset(cmd *base.Command, args []string) {
	var prefixes prefixFlags
	setSharedFlags(cmd)
	cmd.Flag.Var(&prefixes, "p", "")
	cmd.Flag.Var(&prefixes, "prefix", "")
	cmd.Flag.Parse(args)
	tags := cmd.Flag.Args()
	for _, p := range prefixes {
		if p == "" {
			base.Fatalf("empty prefix")
		}
	}
	if len(tags) == 0 && len(prefixes) == 0 {
		base.Fatalf("specify outbound tags and/or -prefix")
	}

	conn, ctx, close := dialAPIServer()
	defer close()
	client := observatoryService.NewObservatoryServiceClient(conn)
	resp, err := client.ResetOutboundStatus(ctx, &observatoryService.ResetOutboundStatusRequest{
		Tags:     tags,
		Prefixes: prefixes,
	})
	if err != nil {
		base.Fatalf("failed to reset observatory results: %s", err)
	}

	if apiJSON {
		showJSONResponse(resp)
		return
	}
	fmt.Printf("reset %d outbounds\n", len(resp.Tags))
	for _, t := range resp.Tags {
		fmt.Println(t)
	}
}
