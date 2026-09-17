package xdrive

import (
	"context"
	gotls "crypto/tls"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func recordingTLSListener(t *testing.T, sni *string, mu *sync.Mutex) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			cfg := &gotls.Config{
				GetConfigForClient: func(hello *gotls.ClientHelloInfo) (*gotls.Config, error) {
					mu.Lock()
					*sni = hello.ServerName
					mu.Unlock()
					return nil, nil
				},
			}
			tconn := gotls.Server(conn, cfg)
			tconn.HandshakeContext(context.Background())
			tconn.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}

func sniForSettings(t *testing.T, serverName string) string {
	t.Helper()

	var (
		sni string
		mu  sync.Mutex
	)
	ln := recordingTLSListener(t, &sni, &mu)
	addr := ln.Addr().(*net.TCPAddr)

	settings := &internet.MemoryStreamConfig{
		ProtocolName: protocolName,
		Destination: &xnet.Destination{
			Address: xnet.ParseAddress(addr.IP.String()),
			Port:    xnet.Port(addr.Port),
			Network: xnet.Network_TCP,
		},
		SecuritySettings: &tls.Config{ServerName: serverName},
	}

	prev := driveFilesURL
	driveFilesURL = "https://www.googleapis.com/drive/v3/files"
	defer func() { driveFilesURL = prev }()

	client := newServiceClient(settings, 5*time.Second, 8)
	req, err := http.NewRequest(http.MethodGet, driveFilesURL, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	client.Do(req)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := sni
		mu.Unlock()
		if got != "" {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	return ""
}

func TestServiceSNIDefaultsToHost(t *testing.T) {
	if got := sniForSettings(t, ""); got != "www.googleapis.com" {
		t.Fatalf("SNI defaulted to %q, want the host www.googleapis.com, not address", got)
	}
}

func TestServiceSNIOverride(t *testing.T) {
	if got := sniForSettings(t, "www.google.com"); got != "www.google.com" {
		t.Fatalf("explicit serverName gave SNI %q, want www.google.com", got)
	}
}
