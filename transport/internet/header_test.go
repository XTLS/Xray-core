package internet_test

import (
	"testing"

	"github.com/4nd3r5on/Xray-core/common"
	. "github.com/4nd3r5on/Xray-core/transport/internet"
	"github.com/4nd3r5on/Xray-core/transport/internet/headers/noop"
	"github.com/4nd3r5on/Xray-core/transport/internet/headers/srtp"
	"github.com/4nd3r5on/Xray-core/transport/internet/headers/utp"
	"github.com/4nd3r5on/Xray-core/transport/internet/headers/wechat"
	"github.com/4nd3r5on/Xray-core/transport/internet/headers/wireguard"
)

func TestAllHeadersLoadable(t *testing.T) {
	testCases := []struct {
		Input interface{}
		Size  int32
	}{
		{
			Input: new(noop.Config),
			Size:  0,
		},
		{
			Input: new(srtp.Config),
			Size:  4,
		},
		{
			Input: new(utp.Config),
			Size:  4,
		},
		{
			Input: new(wechat.VideoConfig),
			Size:  13,
		},
		{
			Input: new(wireguard.WireguardConfig),
			Size:  4,
		},
	}

	for _, testCase := range testCases {
		header, err := CreatePacketHeader(testCase.Input)
		common.Must(err)
		if header.Size() != testCase.Size {
			t.Error("expected size ", testCase.Size, " but got ", header.Size())
		}
	}
}
