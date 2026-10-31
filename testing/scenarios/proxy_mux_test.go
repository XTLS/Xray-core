package scenarios

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

func TestSocksMuxConcurrentWrites(t *testing.T) {
	testMuxConcurrentWrites(t, "socks")
}

func testMuxConcurrentWrites(t *testing.T, protocol string) {
	t.Helper()
	echo := &tcp.Server{MsgProcessor: xor}
	dest, err := echo.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	serverPort, clientPort := tcp.PickPort(), tcp.PickPort()
	for _, config := range []string{
		fmt.Sprintf(`{
			"inbounds": [{"listen": "127.0.0.1", "port": %d, "protocol": "%s", "streamSettings": {"network": "ws"}}],
			"outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]
		}`, serverPort, protocol),
		fmt.Sprintf(`{
			"inbounds": [{"listen": "127.0.0.1", "port": %d, "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1", "port": %d, "network": "tcp"}}],
			"outbounds": [{"protocol": "%s", "settings": {"servers": [{"address": "127.0.0.1", "port": %d}]}, "streamSettings": {"network": "ws"}, "mux": {"enabled": true, "concurrency": 8}}]
		}`, clientPort, dest.Port, protocol, serverPort),
	} {
		cfg, err := serial.LoadJSONConfig(strings.NewReader(config))
		if err != nil {
			t.Fatal(err)
		}
		instance, err := core.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = instance.Close() })
		if err := instance.Start(); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for id := range 8 {
		wg.Go(func() {
			conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", clientPort.String()))
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Error(err)
				return
			}
			payload := bytes.Repeat([]byte{byte(id)}, 32*1024)
			response := make([]byte, len(payload))
			for range 8 {
				if _, err := conn.Write(payload); err != nil {
					t.Error(err)
					return
				}
				if _, err := io.ReadFull(conn, response); err != nil {
					t.Error(err)
					return
				}
				if !bytes.Equal(response, xor(payload)) {
					t.Errorf("corrupted response for session %d", id)
					return
				}
			}
		})
	}
	wg.Wait()
}
