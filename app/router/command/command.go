package command

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import (
	"context"
	"github.com/xtls/xray-core/features/outbound"
	"time"

	"google.golang.org/grpc"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
)

// routingServer is an implementation of RoutingService.
type routingServer struct {
	s            *core.Instance
	ohm          outbound.Manager
	router       routing.Router
	routingStats stats.Channel
}

// NewRoutingServer creates a statistics service with statistics manager.
func NewRoutingServer(router routing.Router, routingStats stats.Channel) RoutingServiceServer {
	return &routingServer{
		router:       router,
		routingStats: routingStats,
	}
}

func (s *routingServer) TestRoute(ctx context.Context, request *TestRouteRequest) (*RoutingContext, error) {
	if request.RoutingContext == nil {
		return nil, newError("Invalid routing request.")
	}
	route, err := s.router.PickRoute(AsRoutingContext(request.RoutingContext))
	if err != nil {
		return nil, err
	}
	if request.PublishResult && s.routingStats != nil {
		ctx, _ := context.WithTimeout(context.Background(), 4*time.Second)
		s.routingStats.Publish(ctx, route)
	}
	return AsProtobufMessage(request.FieldSelectors)(route), nil
}

func (s *routingServer) AddRoutingRule(ctx context.Context, request *AddRoutingRuleRequest) (*AddRoutingRuleResponse, error) {
	if request.RoutingRule == nil {
		return nil, newError("Invalid RoutingRule request.")
	}
	err := s.router.AddRoutingRule(ctx, request.RoutingRule)
	if err != nil {
		return nil, err
	}
	return &AddRoutingRuleResponse{}, nil
}

func (s *routingServer) AlterRoutingRule(ctx context.Context, request *AlterRoutingRuleRequest) (*AlterRoutingRuleResponse, error) {
	if request.RoutingRule == nil {
		return nil, newError("Invalid RoutingRule request.")
	}

	if len(request.Tag) == 0 {
		return nil, newError("Invalid Tag.")
	}

	err := s.router.AlterRoutingRule(ctx, request.Tag, request.RoutingRule)
	if err != nil {
		return nil, err
	}
	return &AlterRoutingRuleResponse{}, nil
}

func (s *routingServer) RemoveRoutingRule(ctx context.Context, request *RemoveRoutingRuleRequest) (*RemoveRoutingRuleResponse, error) {
	if len(request.Tag) == 0 {
		return nil, newError("Invalid Tag.")
	}
	err := s.router.RemoveRoutingRule(ctx, request.Tag)
	if err != nil {
		return nil, err
	}
	return &RemoveRoutingRuleResponse{}, nil
}

func (s *routingServer) AddBalancingRule(ctx context.Context, request *AddBalancingRuleRequest) (*AddBalancingRuleResponse, error) {
	if request.Balancing == nil {
		return nil, newError("Invalid Balancing request.")
	}

	err := s.router.AddBalancingRule(ctx, request.Balancing, s.ohm)
	if err != nil {
		return nil, err
	}
	return &AddBalancingRuleResponse{}, nil
}

func (s *routingServer) AlterBalancingRule(ctx context.Context, request *AlterBalancingRuleRequest) (*AlterBalancingRuleResponse, error) {
	if request.Balancing == nil {
		return nil, newError("Invalid Balancing request.")
	}

	if len(request.Tag) == 0 {
		return nil, newError("Invalid Tag.")
	}
	err := s.router.AlterBalancingRule(ctx, request.Tag, request.Balancing, s.ohm)
	if err != nil {
		return nil, err
	}
	return &AlterBalancingRuleResponse{}, nil
}

func (s *routingServer) RemoveBalancingRule(ctx context.Context, request *RemoveBalancingRuleRequest) (*RemoveBalancingRuleResponse, error) {
	if len(request.Tag) == 0 {
		return nil, newError("Invalid Tag.")
	}
	err := s.router.RemoveBalancingRule(ctx, request.Tag)
	if err != nil {
		return nil, err
	}
	return &RemoveBalancingRuleResponse{}, nil
}

func (s *routingServer) SubscribeRoutingStats(request *SubscribeRoutingStatsRequest, stream RoutingService_SubscribeRoutingStatsServer) error {
	if s.routingStats == nil {
		return newError("Routing statistics not enabled.")
	}
	genMessage := AsProtobufMessage(request.FieldSelectors)
	subscriber, err := stats.SubscribeRunnableChannel(s.routingStats)
	if err != nil {
		return err
	}
	defer stats.UnsubscribeClosableChannel(s.routingStats, subscriber)
	for {
		select {
		case value, ok := <-subscriber:
			if !ok {
				return newError("Upstream closed the subscriber channel.")
			}
			route, ok := value.(routing.Route)
			if !ok {
				return newError("Upstream sent malformed statistics.")
			}
			err := stream.Send(genMessage(route))
			if err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (s *routingServer) mustEmbedUnimplementedRoutingServiceServer() {}

type service struct {
	v *core.Instance
}

func (s *service) Register(server *grpc.Server) {
	rs := &routingServer{
		s:            s.v,
		ohm:          nil,
		router:       nil,
		routingStats: nil,
	}

	common.Must(s.v.RequireFeatures(func(router routing.Router, stats stats.Manager, om outbound.Manager) {
		rs.ohm = om
		rs.router = router
	}))

	RegisterRoutingServiceServer(server, rs)
	// For compatibility purposes
	vCoreDesc := RoutingService_ServiceDesc
	vCoreDesc.ServiceName = "v2ray.core.app.router.command.RoutingService"
	server.RegisterService(&vCoreDesc, rs)
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		s := core.MustFromContext(ctx)
		return &service{v: s}, nil
	}))
}
