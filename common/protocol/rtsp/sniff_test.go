package rtsp_test

import (
	"testing"

	. "github.com/xtls/xray-core/common/protocol/rtsp"
)

func TestRTSPHeaders(t *testing.T) {
	cases := []struct {
		input  string
		domain string
		err    bool
	}{
		{
			input: `OPTIONS rtsp://example.com/media.mp4 RTSP/1.0
CSeq: 1
User-Agent: LibVLC/3.0.8`,
			domain: "example.com",
		},
		{
			input: `PLAY rtsp://localhost/media.mp4 RTSP/1.0
CSeq: 2
User-Agent: VLC/3.0.8`,
			domain: "localhost",
		},
		{
			input: `X OPTIONS rtsp://localhost/media.mp4 RTSP/1.0
CSeq: 2
User-Agent: VLC/3.0.8`,
			domain: "",
			err:    true,
		},
	}

	for _, test := range cases {
		header, err := SniffRTSP([]byte(test.input))
		if test.err {
			if err == nil {
				t.Errorf("Expect error but nil, in test: %v", test)
			}
		} else {
			if err != nil {
				t.Errorf("Expect no error but actually %s in test %v", err.Error(), test)
			}
			if header.Domain() != test.domain {
				t.Error("expected domain ", test.domain, " but got ", header.Domain())
			}
		}
	}
}
