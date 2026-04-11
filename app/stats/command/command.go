package command

import (
	"context"
	"runtime"
	"strings"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/strmatcher"
	"github.com/xtls/xray-core/core"
	feature_stats "github.com/xtls/xray-core/features/stats"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// statsServer is an implementation of StatsService.
type statsServer struct {
	stats     feature_stats.Manager
	startTime time.Time
}

func NewStatsServer(manager feature_stats.Manager) StatsServiceServer {
	return &statsServer{
		stats:     manager,
		startTime: time.Now(),
	}
}

func (s *statsServer) GetStats(ctx context.Context, request *GetStatsRequest) (*GetStatsResponse, error) {
	c := s.stats.GetCounter(request.Name)
	if c == nil {
		return nil, status.Error(codes.NotFound, request.Name+" not found.")
	}
	var value int64
	if request.Reset_ {
		value = c.Set(0)
	} else {
		value = c.Value()
	}
	return &GetStatsResponse{
		Stat: &Stat{
			Name:  request.Name,
			Value: value,
		},
	}, nil
}

func (s *statsServer) GetStatsOnline(ctx context.Context, request *GetStatsRequest) (*GetStatsResponse, error) {
	c := s.stats.GetOnlineMap(request.Name)
	if c == nil {
		return nil, status.Error(codes.NotFound, request.Name+" not found.")
	}
	value := int64(c.Count())
	return &GetStatsResponse{
		Stat: &Stat{
			Name:  request.Name,
			Value: value,
		},
	}, nil
}

func (s *statsServer) GetStatsOnlineIpList(ctx context.Context, request *GetStatsRequest) (*GetStatsOnlineIpListResponse, error) {
	c := s.stats.GetOnlineMap(request.Name)

	if c == nil {
		return nil, status.Error(codes.NotFound, request.Name+" not found.")
	}

	ips := make(map[string]int64)
	c.ForEach(func(ip string, lastSeen int64) bool {
		ips[ip] = lastSeen
		return true
	})

	return &GetStatsOnlineIpListResponse{
		Name: request.Name,
		Ips:  ips,
	}, nil
}

func (s *statsServer) GetAllOnlineUsers(ctx context.Context, request *GetAllOnlineUsersRequest) (*GetAllOnlineUsersResponse, error) {
	return &GetAllOnlineUsersResponse{
		Users: s.stats.GetAllOnlineUsers(),
	}, nil
}

func (s *statsServer) GetUsersStats(ctx context.Context, request *GetUsersStatsRequest) (*GetUsersStatsResponse, error) {
	userMap := make(map[string]*UserStat)

	s.stats.VisitOnlineMaps(func(name string, om feature_stats.OnlineMap) bool {
		if om.Count() == 0 {
			return true
		}

		_, rest, _ := strings.Cut(name, ">>>")
		email, _, _ := strings.Cut(rest, ">>>")

		user := &UserStat{Email: email}
		om.ForEach(func(ip string, lastSeen int64) bool {
			user.Ips = append(user.Ips, &OnlineIPEntry{
				Ip:       ip,
				LastSeen: lastSeen,
			})
			return true
		})
		if len(user.Ips) > 0 {
			userMap[email] = user
		}
		return true
	})

	if request.IncludeTraffic {
		for _, u := range userMap {
			u.Traffic = &TrafficUserStat{}
		}
		const (
			prefixUser     = "user>>>"
			suffixUplink   = ">>>traffic>>>uplink"
			suffixDownlink = ">>>traffic>>>downlink"
		)
		s.stats.VisitCounters(func(name string, c feature_stats.Counter) bool {
			var email string
			var isUplink bool

			if strings.HasSuffix(name, suffixUplink) {
				email = name[len(prefixUser) : len(name)-len(suffixUplink)]
				isUplink = true
			} else if strings.HasSuffix(name, suffixDownlink) {
				email = name[len(prefixUser) : len(name)-len(suffixDownlink)]
			} else {
				return true
			}

			u, ok := userMap[email]
			if !ok {
				return true
			}

			var value int64
			if request.Reset_ {
				value = c.Set(0)
			} else {
				value = c.Value()
			}

			if isUplink {
				u.Traffic.Uplink = value
			} else {
				u.Traffic.Downlink = value
			}
			return true
		})
	}

	resp := &GetUsersStatsResponse{}
	for _, u := range userMap {
		resp.Users = append(resp.Users, u)
	}

	return resp, nil
}

func (s *statsServer) QueryStats(ctx context.Context, request *QueryStatsRequest) (*QueryStatsResponse, error) {
	matcher, err := strmatcher.Substr.New(request.Pattern)
	if err != nil {
		return nil, err
	}

	response := &QueryStatsResponse{}

	s.stats.VisitCounters(func(name string, c feature_stats.Counter) bool {
		if matcher.Match(name) {
			var value int64
			if request.Reset_ {
				value = c.Set(0)
			} else {
				value = c.Value()
			}
			response.Stat = append(response.Stat, &Stat{
				Name:  name,
				Value: value,
			})
		}
		return true
	})

	return response, nil
}

func (s *statsServer) GetSysStats(ctx context.Context, request *SysStatsRequest) (*SysStatsResponse, error) {
	var rtm runtime.MemStats
	runtime.ReadMemStats(&rtm)

	uptime := time.Since(s.startTime)

	response := &SysStatsResponse{
		Uptime:       uint32(uptime.Seconds()),
		NumGoroutine: uint32(runtime.NumGoroutine()),
		Alloc:        rtm.Alloc,
		TotalAlloc:   rtm.TotalAlloc,
		Sys:          rtm.Sys,
		Mallocs:      rtm.Mallocs,
		Frees:        rtm.Frees,
		LiveObjects:  rtm.Mallocs - rtm.Frees,
		NumGC:        rtm.NumGC,
		PauseTotalNs: rtm.PauseTotalNs,
	}

	return response, nil
}

func (s *statsServer) mustEmbedUnimplementedStatsServiceServer() {}

type service struct {
	statsManager feature_stats.Manager
}

func (s *service) Register(server *grpc.Server) {
	ss := NewStatsServer(s.statsManager)
	RegisterStatsServiceServer(server, ss)

	// For compatibility purposes
	vCoreDesc := StatsService_ServiceDesc
	vCoreDesc.ServiceName = "v2ray.core.app.stats.command.StatsService"
	server.RegisterService(&vCoreDesc, ss)
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		s := new(service)

		core.RequireFeatures(ctx, func(sm feature_stats.Manager) {
			s.statsManager = sm
		})

		return s, nil
	}))
}
