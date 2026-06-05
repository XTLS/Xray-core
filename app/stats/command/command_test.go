package command_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/xtls/xray-core/app/stats"
	. "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common"
)

func TestGetStats(t *testing.T) {
	m, err := stats.NewManager(context.Background(), &stats.Config{})
	common.Must(err)

	sc, err := m.RegisterCounter("test_counter")
	common.Must(err)

	sc.Set(1)

	s := NewStatsServer(m)

	testCases := []struct {
		name  string
		reset bool
		value int64
		err   bool
	}{
		{
			name: "counterNotExist",
			err:  true,
		},
		{
			name:  "test_counter",
			reset: true,
			value: 1,
		},
		{
			name:  "test_counter",
			value: 0,
		},
	}
	for _, tc := range testCases {
		resp, err := s.GetStats(context.Background(), &GetStatsRequest{
			Name:   tc.name,
			Reset_: tc.reset,
		})
		if tc.err {
			if err == nil {
				t.Error("nil error: ", tc.name)
			}
		} else {
			common.Must(err)
			if r := cmp.Diff(resp.Stat, &Stat{Name: tc.name, Value: tc.value}, cmpopts.IgnoreUnexported(Stat{})); r != "" {
				t.Error(r)
			}
		}
	}
}

func TestQueryStats(t *testing.T) {
	m, err := stats.NewManager(context.Background(), &stats.Config{})
	common.Must(err)

	sc1, err := m.RegisterCounter("test_counter")
	common.Must(err)
	sc1.Set(1)

	sc2, err := m.RegisterCounter("test_counter_2")
	common.Must(err)
	sc2.Set(2)

	sc3, err := m.RegisterCounter("test_counter_3")
	common.Must(err)
	sc3.Set(3)

	s := NewStatsServer(m)
	resp, err := s.QueryStats(context.Background(), &QueryStatsRequest{
		Pattern: "counter_",
	})
	common.Must(err)
	if r := cmp.Diff(resp.Stat, []*Stat{
		{Name: "test_counter_2", Value: 2},
		{Name: "test_counter_3", Value: 3},
	}, cmpopts.SortSlices(func(s1, s2 *Stat) bool { return s1.Name < s2.Name }),
		cmpopts.IgnoreUnexported(Stat{})); r != "" {
		t.Error(r)
	}
}

func TestGetUsersStatsIgnoresInboundScopedMaps(t *testing.T) {
	m, err := stats.NewManager(context.Background(), &stats.Config{})
	common.Must(err)

	userMap, err := m.RegisterOnlineMap("user>>>alice@example.com>>>online")
	common.Must(err)
	userMap.AddIP("198.51.100.1")

	inboundMap, err := m.RegisterOnlineMap("inbound>>>vless-443>>>user>>>alice@example.com>>>online")
	common.Must(err)
	inboundMap.AddIP("198.51.100.2")

	s := NewStatsServer(m)
	resp, err := s.GetUsersStats(context.Background(), &GetUsersStatsRequest{})
	common.Must(err)

	if r := cmp.Diff(resp.Users, []*UserStat{
		{
			Email: "alice@example.com",
			Ips: []*OnlineIPEntry{
				{Ip: "198.51.100.1"},
			},
		},
	}, cmpopts.SortSlices(func(s1, s2 *UserStat) bool { return s1.Email < s2.Email }),
		cmpopts.SortSlices(func(s1, s2 *OnlineIPEntry) bool { return s1.Ip < s2.Ip }),
		cmpopts.IgnoreFields(OnlineIPEntry{}, "LastSeen"),
		cmpopts.IgnoreUnexported(UserStat{}, OnlineIPEntry{})); r != "" {
		t.Error(r)
	}
}
