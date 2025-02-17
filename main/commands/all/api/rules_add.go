package api

import (
	"fmt"

	routerService "github.com/xtls/xray-core/app/router/command"
	cserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdAddRules = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api adrules [--server=127.0.0.1:8080] <c1.json> [c2.json]...",
	Short:       "Add routing rules",
	Long: `
Add routing rules to Xray.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout seconds to call API. Default 3

	-append
		Append to the existing configuration instead of replacing it. Default false

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080 c1.json c2.json
`,
	Run: executeAddRules,
}

func executeAddRules(cmd *base.Command, args []string) {
	var (
		shouldAppend bool
	)
	setSharedFlags(cmd)
	cmd.Flag.BoolVar(&shouldAppend, "append", false, "")
	cmd.Flag.Parse(args)

	unnamedArgs := cmd.Flag.Args()
	if len(unnamedArgs) == 0 {
		fmt.Println("reading from stdin:")
		unnamedArgs = []string{"stdin:"}
	}
	conn, ctx, close := dialAPIServer()
	defer close()

	client := routerService.NewRoutingServiceClient(conn)

	rcs := make([]conf.RouterConfig, 0)
	for _, arg := range unnamedArgs {
		r, err := loadArg(arg)
		if err != nil {
			base.Fatalf("failed to load %s: %s", arg, err)
		}
		conf, err := serial.DecodeJSONConfig(r)
		if err != nil {
			base.Fatalf("failed to decode %s: %s", arg, err)
		}
		rcs = append(rcs, *conf.RouterConfig)
	}
	if len(rcs) == 0 {
		base.Fatalf("no valid rule found in config")
	}
	for _, in := range rcs {

		config, err := in.Build()
		if err != nil {
			base.Fatalf("failed to build conf: %s", err)
		}
		tmsg := cserial.ToTypedMessage(config)
		if tmsg == nil {
			base.Fatalf("failed to format config to TypedMessage.")
		}

		ra := &routerService.AddRuleRequest{
			Config:       tmsg,
			ShouldAppend: shouldAppend,
		}
		resp, err := client.AddRule(ctx, ra)
		if err != nil {
			base.Fatalf("failed to perform AddRule: %s", err)
		}
		showJSONResponse(resp)
	}

}
