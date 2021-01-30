package command

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// routingServer is an implementation of RoutingService.
type routingServer struct {
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

func (s *routingServer) GetBalancers(ctx context.Context, request *GetBalancersRequest) (*GetBalancersResponse, error) {
	h, ok := s.router.(routing.RouterChecker)
	if !ok {
		return nil, status.Errorf(codes.Unavailable, "current router is not a health checker")
	}
	results, err := h.GetBalancersInfo(request.BalancerTags)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	rsp := &GetBalancersResponse{
		Balancers: make([]*BalancerMsg, 0),
	}
	for _, result := range results {
		var override *OverrideSelectingMsg
		if result.Override != nil {
			override = &OverrideSelectingMsg{
				Until:   result.Override.Until.Local().String(),
				Selects: result.Override.Selects,
			}
		}
		stat := &BalancerMsg{
			Tag:              result.Tag,
			StrategySettings: result.Strategy.Settings,
			Titles:           result.Strategy.ValueTitles,
			Override:         override,
			Selects:          make([]*OutboundMsg, 0),
			Others:           make([]*OutboundMsg, 0),
		}
		for _, item := range result.Strategy.Selects {
			stat.Selects = append(stat.Selects, &OutboundMsg{
				Tag:    item.Tag,
				Values: item.Values,
			})
		}
		for _, item := range result.Strategy.Others {
			stat.Others = append(stat.Others, &OutboundMsg{
				Tag:    item.Tag,
				Values: item.Values,
			})
		}
		rsp.Balancers = append(rsp.Balancers, stat)
	}
	return rsp, nil
}
func (s *routingServer) CheckBalancers(ctx context.Context, request *CheckBalancersRequest) (*CheckBalancersResponse, error) {
	h, ok := s.router.(routing.RouterChecker)
	if !ok {
		return nil, status.Errorf(codes.Unavailable, "current router is not a health checker")
	}
	go func() {
		err := h.CheckBalancers(request.BalancerTags)
		if err != nil {
			newError("CheckBalancers error:", err).AtInfo().WriteToLog()
		}
	}()
	return &CheckBalancersResponse{}, nil
}

func (s *routingServer) OverrideSelecting(ctx context.Context, request *OverrideSelectingRequest) (*OverrideSelectingResponse, error) {
	bo, ok := s.router.(routing.BalancingOverrider)
	if !ok {
		return nil, status.Errorf(codes.Unavailable, "current router doesn't support balancing override")
	}
	err := bo.OverrideSelecting(
		request.BalancerTag,
		request.Selectors,
		time.Duration(request.Validity),
	)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	return &OverrideSelectingResponse{}, nil
}

func (s *routingServer) mustEmbedUnimplementedRoutingServiceServer() {}

type service struct {
	v *core.Instance
}

func (s *service) Register(server *grpc.Server) {
	common.Must(s.v.RequireFeatures(func(router routing.Router, stats stats.Manager) {
		rs := NewRoutingServer(router, nil)
		RegisterRoutingServiceServer(server, rs)

		// For compatibility purposes
		vCoreDesc := RoutingService_ServiceDesc
		vCoreDesc.ServiceName = "v2ray.core.app.router.command.RoutingService"
		server.RegisterService(&vCoreDesc, rs)
	}))
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		s := core.MustFromContext(ctx)
		return &service{v: s}, nil
	}))
}
