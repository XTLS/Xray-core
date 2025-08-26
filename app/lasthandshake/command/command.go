package command

import (
	context "context"
	"time"

	"github.com/xtls/xray-core/app/lasthandshake"
	"github.com/xtls/xray-core/common"
	grpc "google.golang.org/grpc"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type lasthandshakeServer struct {
	UnimplementedLasthandshakeServiceServer
	lasthandshake *lasthandshake.LastHandshake
	startTime     time.Time
}

func NewLasthandshakeServer(manager *lasthandshake.LastHandshake) LasthandshakeServiceServer {

	return &lasthandshakeServer{
		lasthandshake: manager,
		startTime:     time.Now(),
	}
}

func (s *lasthandshakeServer) GetLastHandshake(ctx context.Context, _ *emptypb.Empty) (*LastHandshakeResponse, error) {
	if lasthandshake.Global == nil {
		return &LastHandshakeResponse{
			Timestamp: timestamppb.New(time.Time{}),
		}, nil
	}

	t := lasthandshake.Global.Get()
	return &LastHandshakeResponse{
		Timestamp: timestamppb.New(t),
	}, nil
}

type service struct {
	LastHandshakeManager *lasthandshake.LastHandshake
}

func (s *service) Register(server *grpc.Server) {
	ss := NewLasthandshakeServer(s.LastHandshakeManager)
	RegisterLasthandshakeServiceServer(server, ss)
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		s := &service{
			LastHandshakeManager: lasthandshake.Global,
		}

		return s, nil
	}))
}
