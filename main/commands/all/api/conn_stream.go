package api

import (
	"fmt"
	"io"
	"os"

	connService "github.com/xtls/xray-core/app/connectiontracker/command"
	creflect "github.com/xtls/xray-core/common/reflect"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdConnStream = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api connstream [--server=127.0.0.1:8080]",
	Short:       "Stream live connection open/close events",
	Long: `
Subscribe to a live stream of connection lifecycle events from Xray.
Each event is printed as it occurs. Press Ctrl+C to stop.

Arguments:

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout in seconds for calling API. Default 3 (use a larger value
		or 0 for indefinite streaming).

	-json
		Output each event as JSON. Default: human-readable.

Example:

	{{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -timeout 0
`,
	Run: executeConnStream,
}

func executeConnStream(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)

	conn, ctx, close := dialAPIServer()
	defer close()

	client := connService.NewConnTrackerServiceClient(conn)
	stream, err := client.StreamConnections(ctx, &connService.StreamConnectionsRequest{})
	if err != nil {
		base.Fatalf("failed to start stream: %s", err)
	}

	for {
		update, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			base.Fatalf("stream error: %s", err)
		}
		if apiJSON {
			if j, ok := creflect.MarshalToJson(update, true); ok {
				fmt.Println(j)
			} else {
				fmt.Fprintf(os.Stderr, "failed to encode event as JSON\n")
			}
		} else {
			action := "CONNECTED"
			if update.Event == connService.ConnEventType_DISCONNECTED {
				action = "DISCONNECTED"
			}
			c := update.Conn
			fmt.Printf("[%s] id=%d email=%s protocol=%s inbound=%s\n",
				action, c.GetId(), c.GetEmail(), c.GetProtocol(), c.GetInboundTag())
		}
	}
}
