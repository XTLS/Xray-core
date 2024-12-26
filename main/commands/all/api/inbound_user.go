package api

import (
	handlerService "github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdInboundUser = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api inbounduser [--server=127.0.0.1:8080] -tag=tag [-email=email]",
	Short:       "Get Inbound User",
	Long: `
Get User info from an inbound.
Arguments:
	-s, -server 
		The API server address. Default 127.0.0.1:8080
	-t, -timeout
		Timeout seconds to call API. Default 3
	-tag
	    Inbound tag
    -email
		User email. If email is not given, will get all users
Example:
    {{.Exec}} {{.LongName}} --server=127.0.0.1:8080 -tag="tag name" -email="xray@love.com"
`,
	Run: executeInboundUser,
}

func executeInboundUser(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	var tag string
	var email string
	cmd.Flag.StringVar(&tag, "tag", "", "")
	cmd.Flag.StringVar(&email, "email", "", "")
	cmd.Flag.Parse(args)

	conn, ctx, close := dialAPIServer()
	defer close()

	client := handlerService.NewHandlerServiceClient(conn)
	r := &handlerService.GetInboundUserRequest{
		Tag:   tag,
		Email: email,
	}
	resp, err := client.GetInboundUsers(ctx, r)
	if err != nil {
		base.Fatalf("failed to get inbound user: %s", err)
	}
	showJSONResponse(resp)
}
