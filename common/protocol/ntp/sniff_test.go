package ntp_test

import (
	"encoding/hex"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/ntp"
)

func TestSniffNTP(t *testing.T) {
	pkt, err := hex.DecodeString("1b0203e800000000000000000000000000000000000000000000000000000000000000000000000000")
	common.Must(err)
	_, err = ntp.SniffNTP(pkt)
	if err != nil {
		t.Error("failed to parse NTP packet")
	}
}
