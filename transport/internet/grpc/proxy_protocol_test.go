package grpc

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func TestTrustedSourcesUDSFailsSynchronously(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xray.sock")
	listener, err := Listen(context.Background(), net.DomainAddress(path), 0, &internet.MemoryStreamConfig{
		ProtocolName:     "grpc",
		ProtocolSettings: &Config{},
		SocketSettings: &internet.SocketConfig{
			ProxyProtocolMode:           internet.SocketConfig_ProxyProtocolTrustedSources,
			ProxyProtocolTrustedSources: []string{"127.0.0.1"},
		},
	}, nil)
	if listener != nil {
		_ = listener.Close()
		t.Fatal("unexpected gRPC UDS listener")
	}
	if err == nil {
		t.Fatal("expected source-aware gRPC UDS validation error")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("gRPC reported an error but left a UDS socket behind: %v", statErr)
	}
}

func TestTrustedSourcesInvalidTCPConfigFailsSynchronously(t *testing.T) {
	listener, err := Listen(context.Background(), net.LocalHostIP, 24443, &internet.MemoryStreamConfig{
		ProtocolName:     "grpc",
		ProtocolSettings: &Config{},
		SocketSettings: &internet.SocketConfig{
			ProxyProtocolMode: internet.SocketConfig_ProxyProtocolTrustedSources,
		},
	}, nil)
	if listener != nil {
		_ = listener.Close()
		t.Fatal("unexpected gRPC TCP listener")
	}
	if err == nil {
		t.Fatal("invalid source-aware gRPC TCP configuration returned success")
	}
}
