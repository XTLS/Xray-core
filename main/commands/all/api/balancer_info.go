package api

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	routerService "github.com/xtls/xray-core/app/router/command"
	creflect "github.com/xtls/xray-core/common/reflect"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdBalancerInfo = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api bi [--server=127.0.0.1:8080] <balancer>...",
	Short:       "Retrieve balancer information",
	Long: `
Retrieve information for one or more balancers, including override target and selectable outbounds.

> Ensure that "RoutingService" is enabled under "config.api.services" in the server configuration.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

	-json
		Output JSON. When multiple balancer tags are provided, the result is a JSON array keyed by tag.

Example:

    {{.Exec}} {{.LongName}} --server=127.0.0.1:8080 balancer1 balancer2
`,
	Run: executeBalancerInfo,
}

type balancerInfoResult struct {
	Tag      string                     `json:"tag,omitempty"`
	Balancer *routerService.BalancerMsg `json:"balancer,omitempty"`
}

func executeBalancerInfo(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)
	tags, err := resolveBalancerInfoTags(cmd.Flag.Args())
	if err != nil {
		base.Fatalf("%s", err)
	}

	conn, ctx, close := dialAPIServer()
	defer close()

	client := routerService.NewRoutingServiceClient(conn)
	results, err := fetchBalancerInfoResults(ctx, client, tags)
	if err != nil {
		base.Fatalf("%s", err)
	}

	if apiJSON {
		output, err := renderBalancerInfoJSON(results)
		if err != nil {
			base.Fatalf("%s", err)
		}
		os.Stdout.WriteString(output)
		return
	}

	os.Stdout.WriteString(renderBalancerInfoResults(results))
}

func resolveBalancerInfoTags(args []string) ([]string, error) {
	if len(args) == 0 {
		return nil, errors.New("balancer tag not specified")
	}
	return args, nil
}

func fetchBalancerInfoResults(ctx context.Context, client routerService.RoutingServiceClient, tags []string) ([]balancerInfoResult, error) {
	results := make([]balancerInfoResult, 0, len(tags))
	for _, tag := range tags {
		resp, err := client.GetBalancerInfo(ctx, &routerService.GetBalancerInfoRequest{Tag: tag})
		if err != nil {
			return nil, fmt.Errorf("failed to get balancer information for %q: %w", tag, err)
		}
		results = append(results, balancerInfoResult{
			Tag:      tag,
			Balancer: resp.GetBalancer(),
		})
	}
	return results, nil
}

func renderBalancerInfoResults(results []balancerInfoResult) string {
	if len(results) == 0 {
		return ""
	}

	if len(results) == 1 {
		return formatBalancerInfo(results[0].Balancer)
	}

	sb := new(strings.Builder)
	for i, result := range results {
		if i > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(result.Tag)
		sb.WriteString(":\n")
		sb.WriteString(formatBalancerInfo(result.Balancer))
	}
	return sb.String()
}

func renderBalancerInfoJSON(results []balancerInfoResult) (string, error) {
	if len(results) == 0 {
		return "", nil
	}

	if len(results) == 1 {
		if j, ok := creflect.MarshalToJson(&routerService.GetBalancerInfoResponse{
			Balancer: results[0].Balancer,
		}, true); ok {
			return j, nil
		}
		return "", errors.New("error encode json")
	}

	if j, ok := creflect.MarshalToJson(results, true); ok {
		return j, nil
	}

	return "", errors.New("error encode json")
}

func formatBalancerInfo(b *routerService.BalancerMsg) string {
	const tableIndent = 4
	if b == nil {
		return ""
	}
	sb := new(strings.Builder)
	// Override
	if b.Override != nil {
		sb.WriteString("  - Selecting Override:\n")
		for i, s := range []string{b.Override.Target} {
			writeRow(sb, tableIndent, i+1, []string{s}, nil)
		}
	}
	// Selects
	sb.WriteString("  - Selects:\n")
	if b.PrincipleTarget != nil {
		for i, o := range b.PrincipleTarget.Tag {
			writeRow(sb, tableIndent, i+1, []string{o}, nil)
		}
	}
	return sb.String()
}

func getColumnFormats(titles []string) []string {
	w := make([]string, len(titles))
	for i, t := range titles {
		w[i] = fmt.Sprintf("%%-%ds ", len(t))
	}
	return w
}

func writeRow(sb *strings.Builder, indent, index int, values, formats []string) {
	if index == 0 {
		// title line
		sb.WriteString(strings.Repeat(" ", indent+4))
	} else {
		sb.WriteString(fmt.Sprintf("%s%-4d", strings.Repeat(" ", indent), index))
	}
	for i, v := range values {
		format := "%-14s"
		if i < len(formats) {
			format = formats[i]
		}
		sb.WriteString(fmt.Sprintf(format, v))
	}
	sb.WriteByte('\n')
}
