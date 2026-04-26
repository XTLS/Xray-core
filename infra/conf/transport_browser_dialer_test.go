package conf_test

import (
	"net"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
)

const testBrowserDialerPath = "/123e4567-e89b-12d3-a456-426614174000"

func TestStreamConfigBuildRejectsBrowserDialerUnsupportedProtocol(t *testing.T) {
	network := TransportProtocol("tcp")
	config := &StreamConfig{
		Network: &network,
		SocketSettings: &SocketConfig{
			BrowserDialer: "127.0.0.1:18080" + testBrowserDialerPath,
		},
	}

	_, err := config.Build()
	if err == nil || !strings.Contains(err.Error(), "sockopt.browserDialer only supports websocket or splithttp") {
		t.Fatalf("expected unsupported protocol error, got: %v", err)
	}
}

func TestStreamConfigBuildRejectsBrowserDialerWithREALITY(t *testing.T) {
	network := TransportProtocol("splithttp")
	config := &StreamConfig{
		Network:  &network,
		Security: "reality",
		SocketSettings: &SocketConfig{
			BrowserDialer: "127.0.0.1:18081" + testBrowserDialerPath,
		},
	}

	_, err := config.Build()
	if err == nil || !strings.Contains(err.Error(), "sockopt.browserDialer does not support REALITY") {
		t.Fatalf("expected REALITY rejection, got: %v", err)
	}
}

func TestStreamConfigBuildFailsOnBrowserDialerAddressConflict(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to prepare occupied listener: %v", err)
	}
	defer listener.Close()

	network := TransportProtocol("websocket")
	config := &StreamConfig{
		Network: &network,
		SocketSettings: &SocketConfig{
			BrowserDialer: listener.Addr().String() + testBrowserDialerPath,
		},
	}

	_, err = config.Build()
	if err == nil || !strings.Contains(err.Error(), "Failed to start Browser Dialer listener") {
		t.Fatalf("expected address conflict error, got: %v", err)
	}
}
