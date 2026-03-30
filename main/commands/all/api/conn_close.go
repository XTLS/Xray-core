package api

import (
	"fmt"

	connService "github.com/xtls/xray-core/app/connectiontracker/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdConnClose = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api connclose [--server=127.0.0.1:8080] -id <id>",
	Short:       "Close an active connection by ID",
	Long: `
Force-close an active proxy connection by its numeric ID.
Use 'connlist' to find connection IDs.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3

	-id <uint32>
		The connection ID to close (required).

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -id 42
`,
	Run: executeConnClose,
}

func executeConnClose(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	id := cmd.Flag.Uint("id", 0, "")
	cmd.Flag.Parse(args)

	if *id == 0 {
		base.Fatalf("connection id is required and must be non-zero")
	}

	conn, ctx, close := dialAPIServer()
	defer close()

	client := connService.NewConnTrackerServiceClient(conn)
	resp, err := client.CloseConnection(ctx, &connService.CloseConnectionRequest{
		Id: uint32(*id),
	})
	if err != nil {
		base.Fatalf("failed to close connection: %s", err)
	}
	if apiJSON {
		showJSONResponse(resp)
	} else if resp.Found {
		fmt.Printf("connection %d closed\n", *id)
	} else {
		fmt.Printf("connection %d not found\n", *id)
	}
}
