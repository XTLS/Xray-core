package conf

import (
	"github.com/golang/protobuf/proto"

	"github.com/xtls/xray-core/transport/internet/grpc"
)

type GRPCConfig struct {
	ServiceName string `json:"serviceName"`
	MultiMode   bool   `json:"multiMode"`
}

func (g GRPCConfig) Build() (proto.Message, error) {
	return &grpc.Config{ServiceName: g.ServiceName, MultiMode: g.MultiMode}, nil
}
