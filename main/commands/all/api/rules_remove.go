package api

import (
	routerService "github.com/xtls/xray-core/app/router/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdRemoveRules = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api rmrules [--server=127.0.0.1:8080] [-i index | ruleTag...]",
	Short:       "Remove routing rules by index or ruleTag",
	Long: `
Remove routing rules by zero-based index or ruleTag from Xray.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

	-i, -index <index>
		Remove the rule at this zero-based index.
		This option is mutually exclusive with ruleTag arguments.

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080 ruleTag1 ruleTag2
	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -i 2
`,
	Run: executeRemoveRules,
}

func executeRemoveRules(cmd *base.Command, args []string) {
	removeIndex := -1
	setSharedFlags(cmd)
	cmd.Flag.IntVar(&removeIndex, "i", -1, "")
	cmd.Flag.IntVar(&removeIndex, "index", -1, "")
	cmd.Flag.Parse(args)
	if removeIndex < -1 {
		base.Fatalf("index must be zero or greater")
	}
	ruleTags := cmd.Flag.Args()
	if removeIndex >= 0 && len(ruleTags) > 0 {
		base.Fatalf("-i/-index and ruleTag arguments cannot be used together")
	}
	conn, ctx, close := dialAPIServer()
	defer close()

	client := routerService.NewRoutingServiceClient(conn)

	if removeIndex >= 0 {
		index := uint32(removeIndex)
		resp, err := client.RemoveRule(ctx, &routerService.RemoveRuleRequest{Index: &index})
		if err != nil {
			base.Fatalf("failed to perform RemoveRule: %s", err)
		}
		showJSONResponse(resp)
		return
	}

	if len(ruleTags) == 0 {
		base.Fatalf("no valid ruleTag input")
	}
	for _, tag := range ruleTags {

		rr := &routerService.RemoveRuleRequest{
			RuleTag: tag,
		}
		resp, err := client.RemoveRule(ctx, rr)
		if err != nil {
			base.Fatalf("failed to perform RemoveRule: %s", err)
		}
		showJSONResponse(resp)
	}
}
