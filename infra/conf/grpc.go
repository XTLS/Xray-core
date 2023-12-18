package conf

import (
	"github.com/xtls/xray-core/transport/internet/grpc"
	"google.golang.org/protobuf/proto"
)

type GRPCConfig struct {
	ServiceName         string `json:"serviceName,omitempty"`
	MultiMode           bool   `json:"multiMode,omitempty"`
	IdleTimeout         int32  `json:"idle_timeout,omitempty"`
	HealthCheckTimeout  int32  `json:"health_check_timeout,omitempty"`
	PermitWithoutStream bool   `json:"permit_without_stream,omitempty"`
	InitialWindowsSize  int32  `json:"initial_windows_size,omitempty"`
	UserAgent           string `json:"user_agent,omitempty"`
}

func (g *GRPCConfig) Build() (proto.Message, error) {
	if g.IdleTimeout <= 0 {
		g.IdleTimeout = 0
	}
	if g.HealthCheckTimeout <= 0 {
		g.HealthCheckTimeout = 0
	}
	if g.InitialWindowsSize < 0 {
		// default window size of gRPC-go
		g.InitialWindowsSize = 0
	}

	return &grpc.Config{
		ServiceName:         g.ServiceName,
		MultiMode:           g.MultiMode,
		IdleTimeout:         g.IdleTimeout,
		HealthCheckTimeout:  g.HealthCheckTimeout,
		PermitWithoutStream: g.PermitWithoutStream,
		InitialWindowsSize:  g.InitialWindowsSize,
		UserAgent:           g.UserAgent,
	}, nil
}
