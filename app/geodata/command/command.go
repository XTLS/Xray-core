package command

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata"
	grpc "google.golang.org/grpc"
)

type geodataServer struct{}

func (s *geodataServer) ReloadGeoIP(ctx context.Context, request *ReloadGeoIPRequest) (*ReloadGeoIPResponse, error) {
	if err := geodata.IPReg.Reload(); err != nil {
		return nil, errors.New("failed to reload GeoIP").Base(err)
	}
	return &ReloadGeoIPResponse{}, nil
}

func (s *geodataServer) ReloadGeoSite(ctx context.Context, request *ReloadGeoSiteRequest) (*ReloadGeoSiteResponse, error) {
	if err := geodata.DomainReg.Reload(); err != nil {
		return nil, errors.New("failed to reload GeoSite").Base(err)
	}
	return &ReloadGeoSiteResponse{}, nil
}

func (s *geodataServer) mustEmbedUnimplementedGeodataServiceServer() {}

type service struct{}

func (s service) Register(server *grpc.Server) {
	gs := &geodataServer{}
	RegisterGeodataServiceServer(server, gs)

	// For compatibility purposes
	vCoreDesc := GeodataService_ServiceDesc
	vCoreDesc.ServiceName = "v2ray.core.app.geodata.command.GeodataService"
	server.RegisterService(&vCoreDesc, gs)
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return service{}, nil
	}))
}
