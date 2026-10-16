package dispatcher

import (
	"context"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/features/stats"
)

func TestOnlineProfilesReferenceCountsAndNATIsolation(t *testing.T) {
	m, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	ctx3, cancel3 := context.WithCancel(context.Background())
	defer cancel3()
	ctx4, cancel4 := context.WithCancel(context.Background())
	defer cancel4()
	trackOnlineIP(ctx1, m, "alice", "192.0.2.1", "vless")
	trackOnlineIP(ctx2, m, "alice", "192.0.2.1", "vless")
	trackOnlineIP(ctx3, m, "alice", "192.0.2.1", "hysteria")
	trackOnlineIP(ctx4, m, "bob", "192.0.2.1", "trojan")
	wait := func(email, tag string, want int) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for {
			om := m.GetOnlineMap(stats.InboundOnlineName(email, tag))
			if om != nil && om.Count() == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s/%s did not reach count %d", email, tag, want)
			}
			time.Sleep(time.Millisecond)
		}
	}
	cancel1()
	wait("alice", "vless", 1)
	cancel2()
	wait("alice", "vless", 0)
	wait("alice", "hysteria", 1)
	wait("bob", "trojan", 1)
	cancel3()
	wait("alice", "hysteria", 0)
	if m.GetOnlineMap("user>>>alice>>>online").Count() != 0 {
		t.Fatal("closed user remains online")
	}
	if m.GetOnlineMap("user>>>bob>>>online").Count() != 1 {
		t.Fatal("same NAT IP mixed client identities")
	}
	cancel4()
	wait("bob", "trojan", 0)
}
