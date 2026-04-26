package serial_test

import (
	"testing"

	. "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet/finalmask/header/custom"
)

func TestGetInstance(t *testing.T) {
	p, err := GetInstance("")
	if p != nil {
		t.Error("expected nil instance, but got ", p)
	}
	if err == nil {
		t.Error("expect non-nil error, but got nil")
	}
}

func TestConvertingNilMessage(t *testing.T) {
	x := ToTypedMessage(nil)
	if x != nil {
		t.Error("expect nil, but actually not")
	}
}

func TestTypedMessageRoundTripPreservesFinalmaskCustomUDPMode(t *testing.T) {
	msg := &custom.UDPConfig{
		Mode: "standalone",
		Client: []*custom.UDPItem{
			{Rand: 12, Save: "txid"},
		},
	}

	tm := ToTypedMessage(msg)
	if tm == nil {
		t.Fatal("expected typed message")
	}

	roundTrip, err := tm.GetInstance()
	if err != nil {
		t.Fatalf("GetInstance() failed: %v", err)
	}

	udp, ok := roundTrip.(*custom.UDPConfig)
	if !ok {
		t.Fatalf("unexpected round-trip type: %T", roundTrip)
	}

	if udp.GetMode() != "standalone" {
		t.Fatalf("mode lost during typed message round-trip: got %q", udp.GetMode())
	}
}
