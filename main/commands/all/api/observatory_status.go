package api

import (
	"fmt"
	"sort"

	obsService "github.com/xtls/xray-core/app/observatory/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdObservatoryStatus = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api obs [--server=127.0.0.1:8080]",
	Short:       "Retrieve observatory outbound status",
	Long: `
Retrieve outbound status from observatory, including alive, delay and last error.

> Ensure that "ObservatoryService" is enabled under "config.api.services" in the server configuration.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

Example:

    {{.Exec}} {{.LongName}} --server=127.0.0.1:8080
`,
	Run: executeObservatoryStatus,
}

func executeObservatoryStatus(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)

	conn, ctx, close := dialAPIServer()
	defer close()
	client := obsService.NewObservatoryServiceClient(conn)
	resp, err := client.GetOutboundStatus(ctx, &obsService.GetOutboundStatusRequest{})
	if err != nil {
		base.Fatalf("failed to get observatory status: %s", err)
	}

	if apiJSON {
		showJSONResponse(resp)
		return
	}

	statuses := resp.GetStatus().GetStatus()
	if len(statuses) == 0 {
		fmt.Println("no outbound status available")
		return
	}

	// Sort by outbound tag for stable output
	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].OutboundTag < statuses[j].OutboundTag
	})

	fmt.Printf("%-20s %-6s %-10s %s\n", "TAG", "ALIVE", "DELAY(ms)", "LAST_ERROR")
	fmt.Println("---")

	for _, s := range statuses {
		alive := "no"
		if s.Alive {
			alive = "yes"
		}
		delay := "-"
		if s.Alive && s.Delay > 0 {
			delay = fmt.Sprintf("%d", s.Delay)
		}
		errReason := s.LastErrorReason
		if len(errReason) > 60 {
			errReason = errReason[:60] + "..."
		}
		fmt.Printf("%-20s %-6s %-10s %s\n", s.OutboundTag, alive, delay, errReason)
	}
}
