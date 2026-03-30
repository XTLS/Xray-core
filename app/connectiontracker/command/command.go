package command

import (
	"context"
	"strings"

	grpc "google.golang.org/grpc"

	"github.com/xtls/xray-core/app/connectiontracker"
	"github.com/xtls/xray-core/common"
)

type connTrackerServer struct {
	UnimplementedConnTrackerServiceServer
}

func (s *connTrackerServer) ListConnections(_ context.Context, _ *ListConnectionsRequest) (*ListConnectionsResponse, error) {
	all := connectiontracker.ListAllConnections()
	resp := &ListConnectionsResponse{
		Connections: make([]*ConnInfo, 0, len(all)),
	}
	for _, c := range all {
		resp.Connections = append(resp.Connections, toProto(c))
	}
	return resp, nil
}

func (s *connTrackerServer) CloseConnection(_ context.Context, req *CloseConnectionRequest) (*CloseConnectionResponse, error) {
	found := connectiontracker.CloseGlobalConn(req.Id)
	return &CloseConnectionResponse{Found: found}, nil
}

func (s *connTrackerServer) GetUserStats(_ context.Context, req *GetUserStatsRequest) (*GetUserStatsResponse, error) {
	up, down, count := connectiontracker.GetUserStats(strings.ToLower(req.Email))
	return &GetUserStatsResponse{
		Uplink:    up,
		Downlink:  down,
		ConnCount: count,
	}, nil
}

func (s *connTrackerServer) StreamConnections(_ *StreamConnectionsRequest, stream grpc.ServerStreamingServer[ConnectionUpdate]) error {
	ch := connectiontracker.Subscribe()
	defer connectiontracker.Unsubscribe(ch)

	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-ch:
			if !ok {
				return nil
			}
			evType := ConnEventType_DISCONNECTED
			if ev.Connected {
				evType = ConnEventType_CONNECTED
			}
			if err := stream.Send(&ConnectionUpdate{
				Event: evType,
				Conn:  toProto(ev.Info),
			}); err != nil {
				return err
			}
		}
	}
}

func toProto(c connectiontracker.ConnectionInfo) *ConnInfo {
	return &ConnInfo{
		Id:           c.ID,
		Email:        c.Email,
		InboundTag:   c.InboundTag,
		Protocol:     c.Protocol,
		StartTime:    c.StartTime.Unix(),
		LastActivity: c.LastActivity.Unix(),
		Uplink:       c.Uplink,
		Downlink:     c.Downlink,
	}
}

type service struct{}

func (s *service) Register(server *grpc.Server) {
	RegisterConnTrackerServiceServer(server, &connTrackerServer{})
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(_ context.Context, _ interface{}) (interface{}, error) {
		return &service{}, nil
	}))
}
