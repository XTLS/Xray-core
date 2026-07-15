package dispatcher

import (
	"context"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
)

func TestTrackOnlineIPRetainsDirectSessionSemantics(t *testing.T) {
	manager, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	trackOnlineIP(ctx, manager, "user@example.com", "198.51.100.20")

	online := manager.GetOnlineMap("user>>>user@example.com>>>online")
	if online == nil || online.Count() != 1 {
		t.Fatal("direct session did not acquire an online IP reference")
	}
	var lastSeen int64
	online.ForEach(func(ip string, timestamp int64) bool {
		if ip != "198.51.100.20" {
			t.Fatalf("unexpected online IP: %s", ip)
		}
		lastSeen = timestamp
		return true
	})
	if lastSeen == 0 {
		t.Fatal("direct session did not record acquisition time")
	}

	cancel()
	deadline := time.Now().Add(time.Second)
	for online.Count() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("direct session online IP was not released after context cancellation")
		}
		time.Sleep(time.Millisecond)
	}
}
