package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	logCmd "github.com/xtls/xray-core/app/log/command"
	proxymanCmd "github.com/xtls/xray-core/app/proxyman/command"
	statsCmd "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/vmess"
	"google.golang.org/grpc"
)

var Client *ServiceClient

type ServiceClient struct {
	Address     string
	Port        uint32
	statClient  statsCmd.StatsServiceClient
	proxyClient proxymanCmd.HandlerServiceClient
	logClient   logCmd.LoggerServiceClient
}

func NewServiceClient(addr string, port uint32) *ServiceClient {
	if addr == "" {
		addr = "127.0.0.1"
	}
	if port == 0 {
		return nil
	}
	cmdConn, err := grpc.Dial(fmt.Sprintf("%s:%d", addr, port), grpc.WithInsecure())
	if err != nil {
		newError(err)
		return nil
	}

	svr := ServiceClient{Address: addr, Port: port,
		statClient:  statsCmd.NewStatsServiceClient(cmdConn),
		proxyClient: proxymanCmd.NewHandlerServiceClient(cmdConn),
		logClient:   logCmd.NewLoggerServiceClient(cmdConn),
	}
	return &svr
}

func (h *ServiceClient) QueryStats(pattern string, reset bool) map[string]int64 {
	sresp, err := h.statClient.QueryStats(context.Background(), &statsCmd.QueryStatsRequest{
		Pattern: pattern,
		Reset_:  reset,
	})

	result := make(map[string]int64)
	if err != nil {
		newError("failed to call grpc command: %v", err)
	} else {
		// log.Printf("%v", sresp)
		for _, stat := range sresp.Stat {
			result[stat.Name] = stat.Value
		}
	}

	return result
}

func (h *ServiceClient) GetStats(name string, reset bool) (string, int64) {
	sresp, err := h.statClient.GetStats(context.Background(), &statsCmd.GetStatsRequest{
		Name:   name,
		Reset_: reset,
	})

	if err != nil {
		newError("%v", err)
		return "", 0
	}

	return sresp.Stat.Name, sresp.Stat.Value
}

// AddUser ...
//   Add a user to an inbound on the fly. The effect is not permentnent.
func (h *ServiceClient) AddUser(inboundTag string, email string, level uint32, uuid string, alterID uint32) {
	_, err := h.proxyClient.AlterInbound(context.Background(), &proxymanCmd.AlterInboundRequest{
		Tag: inboundTag,
		Operation: serial.ToTypedMessage(&proxymanCmd.AddUserOperation{
			User: &protocol.User{
				Level: level,
				Email: email,
				Account: serial.ToTypedMessage(&vmess.Account{
					Id:               uuid,
					AlterId:          alterID,
					SecuritySettings: &protocol.SecurityConfig{Type: protocol.SecurityType_AUTO},
				}),
			},
		}),
	})

	if err != nil {
		newError("%v", err)
	}
}

// RemoveUser ...
//   Remove a user from an Inbound on the fly. The effect is not permentnent.
func (h *ServiceClient) RemoveUser(inboundTag string, email string) {
	_, err := h.proxyClient.AlterInbound(context.Background(), &proxymanCmd.AlterInboundRequest{
		Tag: inboundTag,
		Operation: serial.ToTypedMessage(&proxymanCmd.RemoveUserOperation{
			Email: email,
		}),
	})

	if err != nil {
		newError("%v", err)
	}
}

// RestartLogger
// IDK if it will work :D
func (h *ServiceClient) RestartLogger() {
	_, err := h.logClient.RestartLogger(context.Background(), &logCmd.RestartLoggerRequest{})
	if err != nil {
		newError("%v", err)
	}
}

func (h *ServiceClient) AddInbound(in []byte) {
	var ins *conf.InboundDetourConfig
	err := json.Unmarshal(in, &ins)
	if err != nil {
		log.Printf("failed to build conf: %s", err)
	}
	inbound, err := ins.Build()
	if err != nil {
		log.Printf("failed to build conf: %s", err)
	}
	_, err = h.proxyClient.AddInbound(context.Background(), &proxymanCmd.AddInboundRequest{
		Inbound: inbound,
	})
	if err != nil {
		newError("%v", err)
	}
}

func (h *ServiceClient) AddOutbound(in []byte) {
	var ins *conf.OutboundDetourConfig
	err := json.Unmarshal(in, &ins)
	if err != nil {
		log.Printf("failed to build conf: %s", err)
	}
	outbound, err := ins.Build()
	if err != nil {
		log.Printf("failed to build conf: %s", err)
	}
	_, err = h.proxyClient.AddOutbound(context.Background(), &proxymanCmd.AddOutboundRequest{
		Outbound: outbound,
	})
	if err != nil {
		newError("%v", err)
	}
}

func (h *ServiceClient) RemoveInbound(tag string) {
	_, err := h.proxyClient.RemoveInbound(context.Background(), &proxymanCmd.RemoveInboundRequest{
		Tag: tag,
	})
	if err != nil {
		newError("%v", err)
	}
}

func (h *ServiceClient) RemoveOutbound(tag string) {
	_, err := h.proxyClient.RemoveOutbound(context.Background(), &proxymanCmd.RemoveOutboundRequest{
		Tag: tag,
	})
	if err != nil {
		newError("%v", err)
	}
}
