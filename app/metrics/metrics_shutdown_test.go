package metrics

import (
	"bufio"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"testing"
	"time"
)

func TestMetricsClosesKeepAliveConnections(t *testing.T) {
	for _, config := range []*Config{
		{Listen: "127.0.0.1:0"},
		{Tag: "metrics_out"},
		{Listen: "127.0.0.1:0", Tag: "metrics_out"},
	} {
		t.Run(fmt.Sprintf("listen=%t/tag=%t", config.Listen != "", config.Tag != ""), func(t *testing.T) {
			server := startMetricsTestServerWithMetricsConfig(t, config)
			t.Cleanup(func() { _ = server.Close() })
			handler := metricsHandler(t, server)
			var connections []stdnet.Conn
			if config.Listen != "" {
				conn, err := stdnet.DialTimeout("tcp", handler.tcpListener.Addr().String(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				connections = append(connections, conn)
			}
			if config.Tag != "" {
				client, remote := stdnet.Pipe()
				handler.listener.add(remote)
				connections = append(connections, client)
			}
			for _, conn := range connections {
				t.Cleanup(func() { _ = conn.Close() })
				if status, err := readKeepAliveMetrics(conn); err != nil || status != http.StatusOK {
					t.Fatalf("initial metrics request failed: status=%d, error=%v", status, err)
				}
			}
			if err := server.Close(); err != nil {
				t.Fatal(err)
			}
			for _, conn := range connections {
				if status, err := readKeepAliveMetrics(conn); status != 0 || err == nil {
					t.Errorf("closed core still serves metrics on an existing keep-alive connection: status=%d", status)
				} else if err, ok := err.(stdnet.Error); ok && err.Timeout() {
					t.Errorf("metrics connection was not closed: %v", err)
				}
			}
		})
	}
}

func readKeepAliveMetrics(conn stdnet.Conn) (int, error) {
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return 0, err
	}
	if _, err := fmt.Fprint(conn, "GET /debug/vars HTTP/1.1\r\nHost: metrics.test\r\n\r\n"); err != nil {
		return 0, err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, response.Body)
	return response.StatusCode, err
}
