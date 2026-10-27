package command

import (
	"context"
	"strings"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/app/commander"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type service struct {
	UnimplementedFakeDNSServiceServer
	engine dns.FakeDNSEngine
}

func (s *service) GetPools(ctx context.Context, _ *GetPoolsRequest) (*GetPoolsResponse, error) {
	if err := commander.RequireLocal(ctx); err != nil {
		return nil, err
	}
	provider, ok := s.engine.(dns.FakeDNSPoolProvider)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "FakeDNS engine does not expose its pools")
	}
	pools := provider.GetFakeIPRanges()
	if len(pools) == 0 {
		return nil, status.Error(codes.FailedPrecondition, "FakeDNS pools are not initialized")
	}
	return &GetPoolsResponse{IpPools: pools}, nil
}

func (s *service) Allocate(ctx context.Context, request *AllocateRequest) (*AllocateResponse, error) {
	if err := commander.RequireLocal(ctx); err != nil {
		return nil, err
	}
	domain := request.GetDomain()
	if _, ok := mdns.IsDomainName(domain); !ok || strings.ContainsAny(domain, "\x00\r\n\t ") {
		return nil, status.Error(codes.InvalidArgument, "invalid domain")
	}
	if !request.GetIpv4() && !request.GetIpv6() {
		return nil, status.Error(codes.InvalidArgument, "select at least one address family")
	}
	engine, ok := s.engine.(dns.FakeDNSEngineRev0)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "FakeDNS engine does not support address families")
	}
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	var ips []net.Address
	if remote, ok := s.engine.(dns.FakeDNSEngineContext); ok {
		var err error
		ips, err = remote.Allocate(ctx, domain, request.Ipv4, request.Ipv6)
		if err != nil {
			return nil, err
		}
	} else {
		ips = engine.GetFakeIPForDomain3(domain, request.Ipv4, request.Ipv6)
	}
	response := &AllocateResponse{}
	for _, ip := range ips {
		response.Ips = append(response.Ips, ip.IP())
	}
	if len(ips) == 0 {
		return nil, status.Error(codes.FailedPrecondition, "no FakeDNS pool available for the requested families")
	}
	return response, nil
}

func (s *service) ReverseLookup(ctx context.Context, request *ReverseLookupRequest) (*ReverseLookupResponse, error) {
	if err := commander.RequireLocal(ctx); err != nil {
		return nil, err
	}
	ip := request.GetIp()
	if len(ip) != 4 && len(ip) != 16 {
		return nil, status.Error(codes.InvalidArgument, "IP address must contain 4 or 16 bytes")
	}
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	var domain string
	if remote, ok := s.engine.(dns.FakeDNSEngineContext); ok {
		var err error
		domain, err = remote.ReverseLookup(ctx, net.IPAddress(ip))
		if err != nil {
			return nil, err
		}
	} else {
		domain = s.engine.GetDomainFromFakeDNS(net.IPAddress(ip))
	}
	return &ReverseLookupResponse{Domain: domain}, nil
}

func (s *service) Register(server *grpc.Server) {
	RegisterFakeDNSServiceServer(server, s)
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, _ interface{}) (interface{}, error) {
		s := &service{}
		if err := core.RequireFeatures(ctx, func(engine dns.FakeDNSEngine) { s.engine = engine }); err != nil {
			return nil, err
		}
		return s, nil
	}))
}
