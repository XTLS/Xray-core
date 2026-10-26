package command

import (
	"context"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/common"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type service struct {
	UnimplementedObservatoryServiceServer
	v *core.Instance

	observatory extension.Observatory
}

func (s *service) GetOutboundStatus(ctx context.Context, request *GetOutboundStatusRequest) (*GetOutboundStatusResponse, error) {
	resp, err := s.observatory.GetObservation(ctx)
	if err != nil {
		return nil, err
	}
	retdata := resp.(*observatory.ObservationResult)
	return &GetOutboundStatusResponse{
		Status: retdata,
	}, nil
}

// observatoryResetter is implemented by burstObservatory.
type observatoryResetter interface {
	Reset(tags, prefixes []string) []string
}

func (s *service) ResetOutboundStatus(ctx context.Context, request *ResetOutboundStatusRequest) (*ResetOutboundStatusResponse, error) {
	if len(request.Tags) == 0 && len(request.Prefixes) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no tags or prefixes to reset")
	}
	r, ok := s.observatory.(observatoryResetter)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "reset is supported by burstObservatory only")
	}
	return &ResetOutboundStatusResponse{
		Tags: r.Reset(request.Tags, request.Prefixes),
	}, nil
}

func (s *service) Register(server *grpc.Server) {
	RegisterObservatoryServiceServer(server, s)
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		s := core.MustFromContext(ctx)
		sv := &service{v: s}
		err := s.RequireFeatures(func(Observatory extension.Observatory) {
			sv.observatory = Observatory
		}, false)
		if err != nil {
			return nil, err
		}
		return sv, nil
	}))
}
