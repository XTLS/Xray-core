package blackhole_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/proxy/blackhole"
)

func TestHTTPResponse(t *testing.T) {
	handler, err := blackhole.New(context.Background(), &blackhole.Config{
		Response: &blackhole.Response{Type: "http"},
	})
	common.Must(err)
	if handler == nil {
		t.Error("expected HTTP response handler")
	}
}
