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
	UsageLine:   "{{.Exec}} api adrules [--server=127.0.0.1:8080] [-i index] <config.json>",
	Short:       "Add routing rules",
	Long: `
Add routing rules to Xray.

Arguments:
	<c1.json> [c2.json]...
		The configs with the rules to be added. Must be in the xray config format and must have the "routing" field

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout seconds to call API. Default 3

	-append
		Append to the existing configuration instead of replacing it. Default false

	-i, -index <index>
		Insert all rules from one config file before the rule at this zero-based index.
		An index equal to the current rule count appends the rules.
		This option is mutually exclusive with -append and accepts only one config file.

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -i 2 rules.json
`,
	Run: executeAddRules,
}

func executeAddRules(cmd *base.Command, args []string) {
	var shouldAppend bool
	insertIndex := -1
	setSharedFlags(cmd)
	cmd.Flag.BoolVar(&shouldAppend, "append", false, "")
	cmd.Flag.IntVar(&insertIndex, "i", -1, "")
	cmd.Flag.IntVar(&insertIndex, "index", -1, "")
	cmd.Flag.Parse(args)
	if insertIndex < -1 {
		base.Fatalf("index must be zero or greater")
	}
	if insertIndex >= 0 && shouldAppend {
		base.Fatalf("-i/-index and -append cannot be used together")
	}

	unnamedArgs := cmd.Flag.Args()
	if len(unnamedArgs) == 0 {
		fmt.Println("reading from stdin:")
		unnamedArgs = []string{"stdin:"}
	}
	if insertIndex >= 0 && len(unnamedArgs) != 1 {
		base.Fatalf("indexed insertion accepts exactly one config file")
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

		if conf.RouterConfig == nil {
			base.Fatalf("failed to add routing rule: config did not have \"routing\" field")
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
		if insertIndex >= 0 {
			index := uint32(insertIndex)
			ra.Index = &index
		}
		resp, err := client.AddRule(ctx, ra)
		if err != nil {
			base.Fatalf("failed to perform AddRule: %s", err)
		}
		showJSONResponse(resp)
	}
}
