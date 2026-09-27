package log_test

import (
	"testing"

	"github.com/xtls/xray-core/common/log"
)

func TestAccessMessageString(t *testing.T) {
	testCases := []struct {
		name    string
		message *log.AccessMessage
		want    string
	}{
		{
			name: "rejected, no traffic",
			message: &log.AccessMessage{
				From:   "1.2.3.4:5678",
				To:     "tcp:example.com:443",
				Status: log.AccessRejected,
				Reason: "invalid user",
			},
			want: "from 1.2.3.4:5678 rejected tcp:example.com:443 invalid user uplink=0 downlink=0",
		},
		{
			name: "accepted, with traffic",
			message: &log.AccessMessage{
				From:     "1.2.3.4:5678",
				To:       "tcp:example.com:443",
				Status:   log.AccessAccepted,
				Detour:   "in >> out",
				Email:    "user@example.com",
				Uplink:   1234,
				Downlink: 5678,
			},
			want: "from 1.2.3.4:5678 accepted tcp:example.com:443 [in >> out] email: user@example.com uplink=1234 downlink=5678",
		},
	}

	for _, tc := range testCases {
		if got := tc.message.String(); got != tc.want {
			t.Error(tc.name, ": got \"", got, "\", want \"", tc.want, "\"")
		}
	}
}
