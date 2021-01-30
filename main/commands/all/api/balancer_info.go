package api

import (
	"fmt"
	"os"
	"sort"
	"strings"

	routerService "github.com/xtls/xray-core/app/router/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdBalancerInfo = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api bi [--server=127.0.0.1:8080] [balancer]...",
	Short:       "balancer information",
	Long: `
Get information of specified balancers, including health, strategy 
and selecting. If no balancer tag specified, get information of 
all balancers.

> Make sure you have "RoutingService" set in "config.api.services" 
of server config.

Arguments:

	-s, -server 
		The API server address. Default 127.0.0.1:8080

	-t, -timeout
		Timeout seconds to call API. Default 3

Example:

    {{.Exec}} {{.LongName}} --server=127.0.0.1:8080 balancer1 balancer2
`,
	Run: executeBalancerInfo,
}

func executeBalancerInfo(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)

	conn, ctx, close := dialAPIServer()
	defer close()

	client := routerService.NewRoutingServiceClient(conn)
	r := &routerService.GetBalancersRequest{BalancerTags: cmd.Flag.Args()}
	resp, err := client.GetBalancers(ctx, r)
	if err != nil {
		base.Fatalf("failed to get health information: %s", err)
	}
	sort.Slice(resp.Balancers, func(i, j int) bool {
		return resp.Balancers[i].Tag < resp.Balancers[j].Tag
	})
	for _, b := range resp.Balancers {
		showBalancerInfo(b)
	}
}

func showBalancerInfo(b *routerService.BalancerMsg) {
	sb := new(strings.Builder)
	// Balancer
	sb.WriteString(fmt.Sprintf("Balancer: %s\n", b.Tag))
	// Strategy
	sb.WriteString("  - Strategy:\n")
	for _, v := range b.StrategySettings {
		sb.WriteString(fmt.Sprintf("    %s\n", v))
	}
	// Override
	if b.Override != nil {
		sb.WriteString("  - Selecting Override:\n")
		until := fmt.Sprintf("until: %s", b.Override.Until)
		writeRow(sb, 0, nil, nil, until)
		for i, s := range b.Override.Selects {
			writeRow(sb, i+1, nil, nil, s)
		}
	}
	formats := getColumnFormats(b.Titles)
	// Selects
	sb.WriteString("  - Selects:\n")
	writeRow(sb, 0, b.Titles, formats, "Tag")
	for i, o := range b.Selects {
		writeRow(sb, i+1, o.Values, formats, o.Tag)
	}
	// Others
	scnt := len(b.Selects)
	if len(b.Others) > 0 {
		sb.WriteString("  - Others:\n")
		writeRow(sb, 0, b.Titles, formats, "Tag")
		for i, o := range b.Others {
			writeRow(sb, scnt+i+1, o.Values, formats, o.Tag)
		}
	}
	os.Stdout.WriteString(sb.String())
}

func getColumnFormats(titles []string) []string {
	w := make([]string, len(titles))
	for i, t := range titles {
		w[i] = fmt.Sprintf("%%-%ds ", len(t))
	}
	return w
}

func writeRow(sb *strings.Builder, index int, values, formats []string, tag string) {
	if index == 0 {
		// title line
		sb.WriteString("        ")
	} else {
		sb.WriteString(fmt.Sprintf("    %-4d", index))
	}
	for i, v := range values {
		format := "%-14s"
		if i < len(formats) {
			format = formats[i]
		}
		sb.WriteString(fmt.Sprintf(format, v))
	}
	sb.WriteString(tag)
	sb.WriteByte('\n')
}
