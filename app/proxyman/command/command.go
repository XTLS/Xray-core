package command

import (
	"context"
	"reflect"
	"sync"

	"github.com/xtls/xray-core/common"
	cserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"

	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy"
	grpc "google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// InboundOperation is the interface for operations that applies to inbound handlers.
type InboundOperation interface {
	// ApplyInbound applies this operation to the given inbound handler.
	ApplyInbound(context.Context, inbound.Handler) error
}

// OutboundOperation is the interface for operations that applies to outbound handlers.
type OutboundOperation interface {
	// ApplyOutbound applies this operation to the given outbound handler.
	ApplyOutbound(context.Context, outbound.Handler) error
}

func getInbound(handler inbound.Handler) (proxy.Inbound, error) {
	gi, ok := handler.(proxy.GetInbound)
	if !ok {
		return nil, newError("can't get inbound proxy from handler.")
	}
	return gi.GetInbound(), nil
}

// ApplyInbound implements InboundOperation.
func (op *AddUserOperation) ApplyInbound(ctx context.Context, handler inbound.Handler) error {
	p, err := getInbound(handler)
	if err != nil {
		return err
	}
	um, ok := p.(proxy.UserManager)
	if !ok {
		return newError("proxy is not a UserManager")
	}
	mUser, err := op.User.ToMemoryUser()
	if err != nil {
		return newError("failed to parse user").Base(err)
	}
	return um.AddUser(ctx, mUser)
}

// ApplyInbound implements InboundOperation.
func (op *RemoveUserOperation) ApplyInbound(ctx context.Context, handler inbound.Handler) error {
	p, err := getInbound(handler)
	if err != nil {
		return err
	}
	um, ok := p.(proxy.UserManager)
	if !ok {
		return newError("proxy is not a UserManager")
	}
	return um.RemoveUser(ctx, op.Email)
}

type handlerServer struct {
	s   *core.Instance
	ihm inbound.Manager
	ohm outbound.Manager
}

func (s *handlerServer) GetAllInbounds(ctx context.Context, request *GetAllInboundsRequest) (*GetAllInboundsResponse, error) {
	configs := make([]*cserial.TypedMessage, 0)
	if hs, err := s.ihm.GetAllHandlers(ctx); err == nil {
		for _, h := range hs {
			if v, ok := configCache.Load(h); ok && v != nil {
				configs = append(configs, v.(*cserial.TypedMessage))
			}
		}
	}
	return &GetAllInboundsResponse{
		Configs: configs,
	}, nil
}

func (s *handlerServer) AddInbound(ctx context.Context, request *AddInboundRequest) (*AddInboundResponse, error) {
	if err := core.AddInboundHandler(s.s, request.Inbound); err != nil {
		cleanupConfigCache(ctx, s)
		return nil, err
	}

	return &AddInboundResponse{}, nil
}

func (s *handlerServer) RemoveInbound(ctx context.Context, request *RemoveInboundRequest) (*RemoveInboundResponse, error) {
	if h, err := s.ihm.GetHandler(ctx, request.Tag); err == nil {
		if _, ok := configCache.LoadAndDelete(h); ok {
			ht := reflect.TypeOf(h)
			newError("remove ", ht, " from cache").AtDebug().WriteToLog()
		}
	}
	return &RemoveInboundResponse{}, s.ihm.RemoveHandler(ctx, request.Tag)
}

func (s *handlerServer) AlterInbound(ctx context.Context, request *AlterInboundRequest) (*AlterInboundResponse, error) {
	rawOperation, err := request.Operation.GetInstance()
	if err != nil {
		return nil, newError("unknown operation").Base(err)
	}
	operation, ok := rawOperation.(InboundOperation)
	if !ok {
		return nil, newError("not an inbound operation")
	}

	handler, err := s.ihm.GetHandler(ctx, request.Tag)
	if err != nil {
		return nil, newError("failed to get handler: ", request.Tag).Base(err)
	}

	return &AlterInboundResponse{}, operation.ApplyInbound(ctx, handler)
}

func (s *handlerServer) GetAllOutbounds(ctx context.Context, request *GetAllOutboundsRequest) (*GetAllOutboundsResponse, error) {
	configs := make([]*cserial.TypedMessage, 0)
	if hs, err := s.ohm.GetAllHandlers(ctx); err == nil {
		for _, h := range hs {
			if v, ok := configCache.Load(h); ok && v != nil {
				configs = append(configs, v.(*cserial.TypedMessage))
			}
		}
	}
	return &GetAllOutboundsResponse{
		Configs: configs,
	}, nil
}

func (s *handlerServer) AddOutbound(ctx context.Context, request *AddOutboundRequest) (*AddOutboundResponse, error) {
	if err := core.AddOutboundHandler(s.s, request.Outbound); err != nil {
		cleanupConfigCache(ctx, s)
		return nil, err
	}
	return &AddOutboundResponse{}, nil
}

func (s *handlerServer) RemoveOutbound(ctx context.Context, request *RemoveOutboundRequest) (*RemoveOutboundResponse, error) {
	h := s.ohm.GetHandler(request.Tag)
	if _, ok := configCache.LoadAndDelete(h); ok {
		ht := reflect.TypeOf(h)
		newError("remove ", ht, " from config cache").AtDebug().WriteToLog()
	}
	return &RemoveOutboundResponse{}, s.ohm.RemoveHandler(ctx, request.Tag)
}

func (s *handlerServer) AlterOutbound(ctx context.Context, request *AlterOutboundRequest) (*AlterOutboundResponse, error) {
	rawOperation, err := request.Operation.GetInstance()
	if err != nil {
		return nil, newError("unknown operation").Base(err)
	}
	operation, ok := rawOperation.(OutboundOperation)
	if !ok {
		return nil, newError("not an outbound operation")
	}

	handler := s.ohm.GetHandler(request.Tag)
	return &AlterOutboundResponse{}, operation.ApplyOutbound(ctx, handler)
}

func (s *handlerServer) mustEmbedUnimplementedHandlerServiceServer() {}

type service struct {
	v *core.Instance
}

func (s *service) Register(server *grpc.Server) {
	hs := &handlerServer{
		s: s.v,
	}
	common.Must(s.v.RequireFeatures(func(im inbound.Manager, om outbound.Manager) {
		hs.ihm = im
		hs.ohm = om
	}))
	RegisterHandlerServiceServer(server, hs)

	// For compatibility purposes
	vCoreDesc := HandlerService_ServiceDesc
	vCoreDesc.ServiceName = "v2ray.core.app.proxyman.command.HandlerService"
	server.RegisterService(&vCoreDesc, hs)
}

var configCache sync.Map

// cleanupConfigCach remove handlers failed to add to inbound or outbound manager
func cleanupConfigCache(ctx context.Context, s *handlerServer) {

	hs := make([]interface{}, 0)
	if ihs, err := s.ihm.GetAllHandlers(ctx); err == nil {
		for _, h := range ihs {
			hs = append(hs, h)
		}
	}
	if ohs, err := s.ohm.GetAllHandlers(ctx); err == nil {
		for _, h := range ohs {
			hs = append(hs, h)
		}
	}

	rm := make([]interface{}, 0)
	configCache.Range(func(key interface{}, _ interface{}) bool {
		for _, h := range hs {
			if h == key {
				return true
			}
		}
		kt := reflect.TypeOf(key)
		newError("remove ", kt, " from cache").AtDebug().WriteToLog()
		rm = append(rm, key)
		return true
	})

	for _, h := range rm {
		configCache.Delete(h)
	}
}

// interceptConfig cache in(out)bound config when handler is created
func interceptConfig(key interface{}, config interface{}) {
	switch key.(type) {
	case inbound.Handler:
		break
	case outbound.Handler:
		break
	default:
		return
	}

	pb, ok := config.(proto.Message)
	if !ok {
		return
	}

	if tmsg := cserial.ToTypedMessage(pb); tmsg != nil {
		kt := reflect.TypeOf(key)
		ct := reflect.TypeOf(config)
		newError("add ", kt, " with config type ", ct, " to cache").AtDebug().WriteToLog()
		configCache.Store(key, tmsg)
	}
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		common.ConfigIntercepterFn = interceptConfig
		s := core.MustFromContext(ctx)
		return &service{v: s}, nil
	}))
}
