package conf

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/trojan"
)

func TestTrojanServerConfigBuildKeepsUserSpeedLimits(t *testing.T) {
	raw := []byte(`{
		"clients": [{
			"password": "password",
			"email": "limited@example.com",
			"speedLimitUpMbps": 50,
			"speedLimitDownMbps": 75
		}]
	}`)

	cfg := new(TrojanServerConfig)
	if err := json.Unmarshal(raw, cfg); err != nil {
		t.Fatal(err)
	}

	msg, err := cfg.Build()
	if err != nil {
		t.Fatal(err)
	}

	built := msg.(*trojan.ServerConfig)
	assertUserSpeedLimits(t, built.Users[0], 50, 75)
}

func TestShadowsocksServerConfigBuildKeepsUserSpeedLimits(t *testing.T) {
	raw := []byte(`{
		"clients": [{
			"method": "chacha20-ietf-poly1305",
			"password": "password",
			"email": "limited@example.com",
			"speedLimitUpMbps": 50,
			"speedLimitDownMbps": 75
		}]
	}`)

	cfg := new(ShadowsocksServerConfig)
	if err := json.Unmarshal(raw, cfg); err != nil {
		t.Fatal(err)
	}

	msg, err := cfg.Build()
	if err != nil {
		t.Fatal(err)
	}

	built := msg.(*shadowsocks.ServerConfig)
	assertUserSpeedLimits(t, built.Users[0], 50, 75)
}

func TestSpeedLimitSnakeCaseFallback(t *testing.T) {
	raw := []byte(`{
		"clients": [{
			"password": "password",
			"email": "limited@example.com",
			"speed_limit_up_mbps": 25,
			"speed_limit_down_mbps": 35
		}]
	}`)

	cfg := new(TrojanServerConfig)
	if err := json.Unmarshal(raw, cfg); err != nil {
		t.Fatal(err)
	}

	msg, err := cfg.Build()
	if err != nil {
		t.Fatal(err)
	}

	built := msg.(*trojan.ServerConfig)
	assertUserSpeedLimits(t, built.Users[0], 25, 35)
}

func assertUserSpeedLimits(t *testing.T, user *protocol.User, wantUp, wantDown uint64) {
	t.Helper()

	if user.SpeedLimitUpMbps != wantUp {
		t.Fatalf("uplink speed limit mismatch: got %d want %d", user.SpeedLimitUpMbps, wantUp)
	}
	if user.SpeedLimitDownMbps != wantDown {
		t.Fatalf("downlink speed limit mismatch: got %d want %d", user.SpeedLimitDownMbps, wantDown)
	}
}
