package extension

import (
	"context"

	"github.com/xtls/xray-core/features"
	"google.golang.org/protobuf/proto"
)

type Observatory interface {
	features.Feature

	GetObservation(ctx context.Context) (proto.Message, error)
}

type ECHStatus struct {
	Enabled      bool
	Accepted     bool
	ServerName   string
	LastTryTime  int64
	LastSeenTime int64
}

type ECHStatusProvider interface {
	GetOutboundECHStatus(ctx context.Context) (map[string]ECHStatus, error)
}

type BurstObservatory interface {
	Observatory
	Check(tag []string)
}

func ObservatoryType() interface{} {
	return (*Observatory)(nil)
}
