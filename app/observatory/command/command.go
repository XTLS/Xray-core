package command

import (
	"context"
	"sort"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
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
	retdata, err := filterObservation(resp, request.OutboundTags)
	if err != nil {
		return nil, err
	}
	return &GetOutboundStatusResponse{
		Status: retdata,
	}, nil
}

func (s *service) ProbeOutboundStatus(ctx context.Context, request *ProbeOutboundStatusRequest) (*ProbeOutboundStatusResponse, error) {
	resp, err := s.observatory.CheckObservation(ctx, request.OutboundTags)
	if err != nil {
		return nil, err
	}
	retdata, err := filterObservation(resp, request.OutboundTags)
	if err != nil {
		return nil, err
	}
	return &ProbeOutboundStatusResponse{Status: retdata}, nil
}

func filterObservation(message proto.Message, tags []string) (*observatory.ObservationResult, error) {
	result, ok := message.(*observatory.ObservationResult)
	if !ok {
		return nil, errors.New("unexpected observatory result type")
	}

	selected := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		selected[tag] = struct{}{}
	}
	filtered := &observatory.ObservationResult{}
	for _, status := range result.Status {
		if status == nil {
			continue
		}
		if len(selected) != 0 {
			if _, found := selected[status.OutboundTag]; !found {
				continue
			}
		}
		filtered.Status = append(filtered.Status, proto.Clone(status).(*observatory.OutboundStatus))
	}
	sort.Slice(filtered.Status, func(i, j int) bool {
		return filtered.Status[i].OutboundTag < filtered.Status[j].OutboundTag
	})
	return filtered, nil
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
