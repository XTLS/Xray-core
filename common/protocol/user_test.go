package protocol_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"google.golang.org/protobuf/proto"
)

func TestUserSpeedLimitsProtoRoundTrip(t *testing.T) {
	user := &protocol.User{
		Level: 1,
		Email: "limited@example.com",
		Account: serial.ToTypedMessage(&shadowsocks.Account{
			Password:   "password",
			CipherType: shadowsocks.CipherType_CHACHA20_POLY1305,
		}),
		SpeedLimitUpMbps:   50,
		SpeedLimitDownMbps: 75,
	}

	payload, err := proto.Marshal(user)
	if err != nil {
		t.Fatal(err)
	}

	decoded := new(protocol.User)
	if err := proto.Unmarshal(payload, decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.SpeedLimitUpMbps != user.SpeedLimitUpMbps {
		t.Fatalf("uplink speed limit mismatch: got %d want %d", decoded.SpeedLimitUpMbps, user.SpeedLimitUpMbps)
	}
	if decoded.SpeedLimitDownMbps != user.SpeedLimitDownMbps {
		t.Fatalf("downlink speed limit mismatch: got %d want %d", decoded.SpeedLimitDownMbps, user.SpeedLimitDownMbps)
	}
}

func TestUserSpeedLimitsJSONCamelCase(t *testing.T) {
	raw := []byte(`{
		"email": "limited@example.com",
		"speedLimitUpMbps": 50,
		"speedLimitDownMbps": 75
	}`)

	user := new(protocol.User)
	if err := json.Unmarshal(raw, user); err != nil {
		t.Fatal(err)
	}

	if user.SpeedLimitUpMbps != 50 {
		t.Fatalf("uplink speed limit mismatch: got %d want 50", user.SpeedLimitUpMbps)
	}
	if user.SpeedLimitDownMbps != 75 {
		t.Fatalf("downlink speed limit mismatch: got %d want 75", user.SpeedLimitDownMbps)
	}
}
