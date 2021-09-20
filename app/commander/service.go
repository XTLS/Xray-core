package commander

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/xtls/xray-core/common"
)

// Service is a Commander service.
type Service interface {
	// Register registers the service itself to a gRPC server.
	Register(*grpc.Server)
}

type reflectionService struct{}

func (r reflectionService) Register(s *grpc.Server) {
	reflection.Register(s)
}

func init() {
	common.Must(common.RegisterConfig((*ReflectionConfig)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return reflectionService{}, nil
	}))
}
