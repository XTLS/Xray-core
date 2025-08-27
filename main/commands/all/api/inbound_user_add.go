package api

import (
	"context"
	"fmt"

	"github.com/xtls/xray-core/common/protocol"

	handlerService "github.com/xtls/xray-core/app/proxyman/command"
	cserial "github.com/xtls/xray-core/common/serial"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	vmessin "github.com/xtls/xray-core/proxy/vmess/inbound"

	"github.com/xtls/xray-core/main/commands/base"
)

var cmdAddInboundUsers = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api adu [--server=127.0.0.1:8080] <c1.json> [c2.json]...",
	Short:       "Add users to inbounds",
	Long: `
Add users to inbounds.
Arguments:
	-s, -server
		The API server address. Default 127.0.0.1:8080
	-t, -timeout
		Timeout seconds to call API. Default 3
Example:
    {{.Exec}} {{.LongName}} --server=127.0.0.1:8080  c1.json c2.json
`,
	Run: executeAddInboundUsers,
}

func executeAddInboundUsers(cmd *base.Command, args []string) {
	setSharedFlags(cmd)
	cmd.Flag.Parse(args)
	unnamedArgs := cmd.Flag.Args()
	inbs := extractInboundsConfig(unnamedArgs)

	conn, ctx, close := dialAPIServer()
	defer close()
	client := handlerService.NewHandlerServiceClient(conn)

	success := 0
	for _, inb := range inbs {
		success += executeInboundUserAction(ctx, client, inb, addInboundUserAction)
	}
	fmt.Println("Added", success, "user(s) in total.")
}

func addInboundUserAction(ctx context.Context, client handlerService.HandlerServiceClient, tag string, user *protocol.User) error {
	fmt.Println("add user:", user.Email)
	_, err := client.AlterInbound(ctx, &handlerService.AlterInboundRequest{
		Tag: tag,
		Operation: cserial.ToTypedMessage(
			&handlerService.AddUserOperation{
				User: user,
			}),
	})
	return err
}

func extractInboundUsers(inb *core.InboundHandlerConfig) []*protocol.User {
	if inb == nil {
		return nil
	}
	inst, err := inb.ProxySettings.GetInstance()
	if err != nil || inst == nil {
		fmt.Println("failed to get inbound instance:", err)
		return nil
	}
	switch ty := inst.(type) {
	case *vmessin.Config:
		return ty.User
	case *vlessin.Config:
		return ty.Clients
	case *trojan.ServerConfig:
		return ty.Users
	case *shadowsocks.ServerConfig:
		return ty.Users
	case *shadowsocks_2022.MultiUserServerConfig:
		return ty.Users
	default:
		fmt.Println("unsupported inbound type")
	}
	return nil
}

func extractInboundsConfig(unnamedArgs []string) []conf.InboundDetourConfig {
	ins := make([]conf.InboundDetourConfig, 0)
	for _, arg := range unnamedArgs {
		r, err := loadArg(arg)
		if err != nil {
			base.Fatalf("failed to load %s: %s", arg, err)
		}
		conf, err := serial.DecodeJSONConfig(r)
		if err != nil {
			base.Fatalf("failed to decode %s: %s", arg, err)
		}
		ins = append(ins, conf.InboundConfigs...)
	}
	return ins
}

func executeInboundUserAction(ctx context.Context, client handlerService.HandlerServiceClient, inb conf.InboundDetourConfig, action func(ctx context.Context, client handlerService.HandlerServiceClient, tag string, user *protocol.User) error) int {
	success := 0

	tag := inb.Tag
	if len(tag) < 1 {
		return success
	}

	fmt.Println("processing inbound:", tag)
	built, err := inb.Build()
	if err != nil {
		fmt.Println("failed to build config:", err)
		return success
	}

	users := extractInboundUsers(built)
	if users == nil {
		return success
	}

	for _, user := range users {
		if len(user.Email) < 1 {
			continue
		}
		if err := action(ctx, client, inb.Tag, user); err == nil {
			fmt.Println("result: ok")
			success += 1
		} else {
			fmt.Println(err)
		}
	}
	return success
}
