package blackhole_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestBlackholeHTTPResponse(t *testing.T) {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	handler, err := blackhole.New(ctx, &blackhole.Config{
		Response: serial.ToTypedMessage(&blackhole.HTTPResponse{}),
	})
	common.Must(err)

	reader, writer := pipe.New(pipe.WithoutSizeLimit())

	var mb buf.MultiBuffer
	var rerr error
	go func() {
		b, e := reader.ReadMultiBuffer()
		mb = b
		rerr = e
	}()

	link := transport.Link{
		Reader: reader,
		Writer: writer,
	}
	common.Must(handler.Process(ctx, &link, nil))
	common.Must(rerr)
	if mb.IsEmpty() {
		t.Error("expect http response, but nothing")
	}
}

func TestBlackholeHTTPResponseWithStatusCode(t *testing.T) {
	testCases := []struct {
		name           string
		statusCode     int32
		expectedStatus string
	}{
		{"Default (403)", 0, "HTTP/1.1 403 Forbidden"},
		{"No Content (204)", 204, "HTTP/1.1 204 No Content"},
		{"OK (200)", 200, "HTTP/1.1 200 OK"},
		{"Not Found (404)", 404, "HTTP/1.1 404 Not Found"},
		{"Internal Server Error (500)", 500, "HTTP/1.1 500 Internal Server Error"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
			handler, err := blackhole.New(ctx, &blackhole.Config{
				Response: serial.ToTypedMessage(&blackhole.HTTPResponse{StatusCode: tc.statusCode}),
			})
			common.Must(err)

			reader, writer := pipe.New(pipe.WithoutSizeLimit())

			var mb buf.MultiBuffer
			var rerr error
			go func() {
				b, e := reader.ReadMultiBuffer()
				mb = b
				rerr = e
			}()

			link := transport.Link{
				Reader: reader,
				Writer: writer,
			}
			common.Must(handler.Process(ctx, &link, nil))
			common.Must(rerr)

			if mb.IsEmpty() {
				t.Error("expect http response, but nothing")
				return
			}

			response := mb.String()
			if len(response) < len(tc.expectedStatus) || response[:len(tc.expectedStatus)] != tc.expectedStatus {
				t.Errorf("expected response to start with %q, got %q", tc.expectedStatus, response)
			}
		})
	}
}
