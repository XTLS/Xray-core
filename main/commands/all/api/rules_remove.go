package api

import (
	"fmt"

	routerService "github.com/xtls/xray-core/app/router/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdRemoveRules = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api rmrules [--server=127.0.0.1:8080] [ruleTag]...",
	Short:       "Remove routing rules by ruleTag",
	Long: `
Remove routing rules by ruleTag from Xray.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080 ruleTag1 ruleTag2
`,
	Run: executeRemoveRules,
}

func executeRemoveRules(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)
	ruleTags := cmd.Flag.Args()
	if len(ruleTags) == 0 {
		fmt.Println("reading from stdin:")
		ruleTags = []string{"stdin:"}
	}
	conn, ctx, close := dialAPIServer()
	defer close()

	client := routerService.NewRoutingServiceClient(conn)

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
