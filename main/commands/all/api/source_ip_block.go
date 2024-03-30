package api

import (
	"encoding/json"
	"fmt"
	"strings"

	routerService "github.com/xtls/xray-core/app/router/command"
	cserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdSourceIpBlock = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api sib [--server=127.0.0.1:8080] -outbound=blocked -inbound=socks 1.2.3.4",
	Short:       "Drop connections by source ip",
	Long: `
Drop connections by source ip.
Arguments:
	-s, -server 
		The API server address. Default 127.0.0.1:8080
	-t, -timeout
		Timeout seconds to call API. Default 3
	-outbound
		route traffic to specific outbound.
	-inbound
		target traffig from specific inbound.
	-ruletag
		set ruleTag. Default sourceIpBlock
	-reset
		remove ruletag and apply new source IPs. Default false

	Example:
    {{.Exec}} {{.LongName}} --server=127.0.0.1:8080 c1.json c2.json
`,
	Run: executeSourceIpBlock,
}

func executeSourceIpBlock(cmd *base.Command, args []string) {
	var (
		inbound  string
		outbound string
		ruletag  string
		reset    bool
	)
	setSharedFlags(cmd)
	cmd.Flag.StringVar(&inbound, "inbound", "", "")
	cmd.Flag.StringVar(&outbound, "outbound", "", "")
	cmd.Flag.StringVar(&ruletag, "ruletag", "sourceIpBlock", "")
	cmd.Flag.BoolVar(&reset, "reset", false, "")

	cmd.Flag.Parse(args)

	unnamedArgs := cmd.Flag.Args()
	if len(unnamedArgs) == 0 {
		fmt.Println("reading from stdin:")
		unnamedArgs = []string{"stdin:"}
	}
	conn, ctx, close := dialAPIServer()
	defer close()

	client := routerService.NewRoutingServiceClient(conn)

	jsonIps, err := json.Marshal(unnamedArgs)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return
	}

	jsonInbound, err := json.Marshal([]string{inbound})
	if inbound == "" {
		jsonInbound, err = json.Marshal([]string{})
	}
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return
	}
	stringConfig := fmt.Sprintf(`
	{
		"routing": {
			"rules": [
			  {
				"ruleTag" : "%s",
				"inboundTag": %s,		
				"outboundTag": "%s",
				"type": "field",
				"source": %s
			  }
			]
		  }
	  }
	  
	`, ruletag, string(jsonInbound), outbound, string(jsonIps))

	conf, err := serial.DecodeJSONConfig(strings.NewReader(stringConfig))
	if err != nil {
		base.Fatalf("failed to decode : %s", err)
	}
	rc := *conf.RouterConfig

	config, err := rc.Build()
	if err != nil {
		base.Fatalf("failed to build conf: %s", err)
	}
	tmsg := cserial.ToTypedMessage(config)
	if tmsg == nil {
		base.Fatalf("failed to format config to TypedMessage.")
	}

	if reset {
		rr := &routerService.RemoveRuleRequest{
			RuleTag: ruletag,
		}
		resp, err := client.RemoveRule(ctx, rr)
		if err != nil {
			base.Fatalf("failed to perform RemoveRule: %s", err)
		}
		showJSONResponse(resp)

	}
	ra := &routerService.AddRuleRequest{
		Config:       tmsg,
		ShouldAppend: true,
	}
	resp, err := client.AddRule(ctx, ra)
	if err != nil {
		base.Fatalf("failed to perform AddRule: %s", err)
	}
	showJSONResponse(resp)

}
