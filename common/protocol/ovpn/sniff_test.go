package ovpn_test

import (
	"encoding/hex"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/ovpn"
)

func TestSniffOpenVPN(t *testing.T) {
	pkt, err := hex.DecodeString("370e0400000102030405060708090a0b0c0d0e0f")
	common.Must(err)
	_, err = ovpn.SniffOpenVPN(pkt)
	if err != nil {
		t.Error("failed to parse OpenVPN packet")
	}
}
