// +build !confonly

package encoding

import (
	"context"

	"google.golang.org/grpc"
)

func ServerDesc(name string) grpc.ServiceDesc {
	return grpc.ServiceDesc{
		ServiceName: name,
		HandlerType: (*GRPCServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Tun",
				Handler:       _GRPCService_Tun_Handler,
				ServerStreams: true,
				ClientStreams: true,
			},
		},
		Metadata: "grpc.proto",
	}
}

func (c *gRPCServiceClient) TunCustomName(ctx context.Context, name string, opts ...grpc.CallOption) (GRPCService_TunClient, error) {
	stream, err := c.cc.NewStream(ctx, &ServerDesc(name).Streams[0], "/"+name+"/Tun", opts...)
	if err != nil {
		return nil, err
	}
	x := &gRPCServiceTunClient{stream}
	return x, nil
}

type GRPCServiceClientX interface {
	TunCustomName(ctx context.Context, name string, opts ...grpc.CallOption) (GRPCService_TunClient, error)
	Tun(ctx context.Context, opts ...grpc.CallOption) (GRPCService_TunClient, error)
}

func RegisterGRPCServiceServerX(s *grpc.Server, srv GRPCServiceServer, name string) {
	desc := ServerDesc(name)
	s.RegisterService(&desc, srv)
}
