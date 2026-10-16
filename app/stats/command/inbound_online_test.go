package command_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/stats"
	. "github.com/xtls/xray-core/app/stats/command"
	featurestats "github.com/xtls/xray-core/features/stats"
)

func TestGetUsersStatsExactInboundAttribution(t *testing.T) {
	m, err := stats.NewManager(context.Background(), &stats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	add := func(name string) {
		om, err := m.GetOrRegisterOnlineMap(name)
		if err != nil {
			t.Fatal(err)
		}
		om.AddIP("192.0.2.1")
	}
	for _, email := range []string{"alice", "bob"} {
		add("user>>>" + email + ">>>online")
	}
	add(featurestats.InboundOnlineName("alice", "vless"))
	add(featurestats.InboundOnlineName("alice", "hysteria"))
	add(featurestats.InboundOnlineName("bob", "trojan"))
	c, _ := m.GetOrRegisterCounter("user>>>alice>>>traffic>>>uplink")
	c.Set(123)
	s := NewStatsServer(m)
	response, err := s.GetUsersStats(context.Background(), &GetUsersStatsRequest{IncludeTraffic: true})
	if err != nil {
		t.Fatal(err)
	}
	if !response.GetInboundTracking() || len(response.Users) != 2 {
		t.Fatalf("capability/users: %v", response)
	}
	if !reflect.DeepEqual(response.Users[0].InboundTags, []string{"hysteria", "vless"}) || !reflect.DeepEqual(response.Users[1].InboundTags, []string{"trojan"}) {
		t.Fatalf("attribution: %v", response)
	}
	if response.Users[0].Traffic.Uplink != 123 || c.Value() != 123 || len(response.Users[0].Ips) != 1 {
		t.Fatal("legacy traffic or IP aggregation changed")
	}
	legacy, _ := s.GetAllOnlineUsers(context.Background(), &GetAllOnlineUsersRequest{})
	for _, name := range legacy.Users {
		if strings.HasPrefix(name, featurestats.InboundOnlinePrefix) {
			t.Fatal("private attribution leaked into legacy API")
		}
	}
	om := m.GetOnlineMap(featurestats.InboundOnlineName("alice", "vless"))
	om.RemoveIP("192.0.2.1")
	response, _ = s.GetUsersStats(context.Background(), &GetUsersStatsRequest{})
	if !reflect.DeepEqual(response.Users[0].InboundTags, []string{"hysteria"}) {
		t.Fatalf("closed inbound persisted: %v", response)
	}
}
